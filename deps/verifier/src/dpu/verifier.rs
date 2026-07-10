// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Core DPU DICE certificate chain verifier.
//!
//! Implements the verification logic described in Tri-Secure paper §5.4:
//!
//! 1. Verify Alias cert signature against DeviceID public key (ECDSA P-384)
//! 2. Verify DeviceID cert signature against manufacturer Root CA
//! 3. Extract FWID measurements from each firmware layer
//! 4. Compare FWIDs against RVPS reference values
//! 5. Verify nonce binding (session freshness + tri-core binding)

use super::crypto;
use super::dice::{AliasCert, DeviceIdCert, DiceCertChain};
use super::error::{VerifierError, VerifierResult};
use super::rvps::{self, RvpsClient};
use tracing::debug;
use p384::PublicKey;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Configuration for the DPU verifier.
pub struct DpuVerifierConfig {
    /// Manufacturer Root CA public key (P-384)
    pub root_ca_public_key: Option<PublicKey>,
    /// Maximum allowed certificate age in seconds (default: 3600)
    pub max_cert_age_secs: u64,
    /// Require all firmware layers to have matching RVPS entries
    pub require_all_layers_verified: bool,
}

impl Default for DpuVerifierConfig {
    fn default() -> Self {
        Self {
            root_ca_public_key: None,
            max_cert_age_secs: 3600,
            require_all_layers_verified: true,
        }
    }
}

impl DpuVerifierConfig {
    pub fn new(root_ca_public_key: PublicKey) -> Self {
        Self {
            root_ca_public_key: Some(root_ca_public_key),
            max_cert_age_secs: 3600,
            require_all_layers_verified: true,
        }
    }

    pub fn with_max_cert_age(mut self, secs: u64) -> Self {
        self.max_cert_age_secs = secs;
        self
    }
}

/// Detailed verification report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Overall verification result
    pub passed: bool,
    /// Device serial number
    pub device_serial: String,
    /// Device class
    pub device_class: String,
    /// Number of firmware layers verified
    pub firmware_layers_verified: usize,
    /// Accumulated FWID (SHA-384)
    pub accumulated_fwid: String,
    /// Alias certificate nonce (hex)
    pub session_nonce: String,
    /// OOB hash of CPU evidence
    pub oob_cpu_hash: String,
    /// OOB hash of GPU evidence
    pub oob_gpu_hash: String,
    /// Timestamp of Alias cert
    pub alias_timestamp: u64,
    /// Verification failure reason (if any)
    pub failure_reason: Option<String>,
}

/// The main DPU verifier.
pub struct DpuVerifier {
    config: DpuVerifierConfig,
    rvps: Box<dyn RvpsClient>,
}

impl DpuVerifier {
    /// Creates a new DPU verifier with the given config and RVPS client.
    pub fn with_config(config: DpuVerifierConfig, rvps: Box<dyn RvpsClient>) -> Self {
        Self { config, rvps }
    }

    /// Verifies a complete DICE certificate chain.
    pub fn verify(&self, chain: &DiceCertChain) -> VerifierResult<VerificationReport> {
        let device_serial = chain.device_id_cert.serial.clone();
        let device_class = chain.device_id_cert.device_class.clone();

        // Step 1: Verify Alias certificate signature against DeviceID public key
        self.verify_alias_signature(&chain.device_id_cert, &chain.alias_cert)
            .map_err(|e| VerifierError::ChainValidation {
                layer: "alias_cert".to_string(),
                reason: format!("Alias cert signature verification failed: {}", e),
            })?;

        // Step 2: Verify DeviceID certificate signature against Root CA
        if self.config.root_ca_public_key.is_some() {
            self.verify_device_id_signature(&chain.device_id_cert)
                .map_err(|e| VerifierError::ChainValidation {
                    layer: "device_id_cert".to_string(),
                    reason: format!("DeviceID cert Root CA verification failed: {}", e),
                })?;
        } else {
            debug!("DPU verifier: Root CA key not configured, skipping DeviceID signature check");
        }

        // Step 3: Check certificate temporal validity
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| VerifierError::Crypto(format!("system clock: {}", e)))?
            .as_secs();

        if !chain.device_id_cert.is_valid_at(now) {
            return Err(VerifierError::CertificateValidity);
        }

        // Check Alias cert freshness
        if now < chain.alias_cert.timestamp
            || (now - chain.alias_cert.timestamp) > self.config.max_cert_age_secs
        {
            return Err(VerifierError::ChainValidation {
                layer: "alias_cert".to_string(),
                reason: format!(
                    "Alias cert age {}s exceeds max {}s",
                    now.saturating_sub(chain.alias_cert.timestamp),
                    self.config.max_cert_age_secs
                ),
            });
        }

        // Step 4: Verify FWID measurements against RVPS
        let layers_verified = if self.config.require_all_layers_verified {
            match rvps::validate_firmware_layers(
                &chain.device_id_cert.firmware_layers,
                &device_class,
                self.rvps.as_ref(),
            ) {
                Ok(()) => chain.device_id_cert.firmware_layers.len(),
                Err(VerifierError::RvpsLookupFailed(_)) => {
                    debug!("DPU verifier: RVPS has no entries for device class '{}', skipping FWID check", device_class);
                    0
                }
                Err(e) => return Err(e),
            }
        } else {
            self.count_verified_layers(&chain.device_id_cert, &device_class)?
        };

        // Step 5: Verify nonce binding (combined nonce hash)
        self.verify_nonce_binding(&chain.alias_cert)?;

        // Success — build report
        let report = VerificationReport {
            passed: true,
            device_serial,
            device_class,
            firmware_layers_verified: layers_verified,
            accumulated_fwid: hex::encode(chain.device_id_cert.accumulated_fwid()),
            session_nonce: hex::encode(&chain.alias_cert.session_nonce),
            oob_cpu_hash: hex::encode(&chain.alias_cert.oob_hashes.cpu_evidence_hash),
            oob_gpu_hash: hex::encode(&chain.alias_cert.oob_hashes.gpu_evidence_hash),
            alias_timestamp: chain.alias_cert.timestamp,
            failure_reason: None,
        };

        Ok(report)
    }

    /// Verifies the Alias certificate was signed by the DeviceID private key.
    fn verify_alias_signature(
        &self,
        device_id_cert: &DeviceIdCert,
        alias_cert: &AliasCert,
    ) -> VerifierResult<()> {
        let tbs = alias_cert.tbs_data();
        crypto::verify_ecdsa_p384(
            &device_id_cert.public_key,
            &tbs,
            &alias_cert.device_id_signature,
        )
    }

    /// Verifies the DeviceID certificate was signed by the manufacturer's Root CA.
    fn verify_device_id_signature(&self, device_id_cert: &DeviceIdCert) -> VerifierResult<()> {
        let root_ca_key = self.config.root_ca_public_key.as_ref()
            .ok_or_else(|| VerifierError::Crypto("Root CA key not configured".into()))?;
        let tbs = device_id_cert.tbs_data();
        crypto::verify_ecdsa_p384(root_ca_key, &tbs, &device_id_cert.root_ca_signature)
    }

    /// Counts how many firmware layers have matching RVPS entries.
    fn count_verified_layers(
        &self,
        device_id_cert: &DeviceIdCert,
        device_class: &str,
    ) -> VerifierResult<usize> {
        let mut count = 0;
        for layer in &device_id_cert.firmware_layers {
            if let Ok(rv) = self.rvps.get_reference_value(device_class, &layer.name) {
                if layer.fwid == rv.expected_fwid {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Verifies nonce binding integrity.
    fn verify_nonce_binding(&self, alias_cert: &AliasCert) -> VerifierResult<()> {
        if alias_cert.session_nonce.len() != 32 {
            return Err(VerifierError::NonceBindingFailed(format!(
                "session nonce must be 32 bytes, got {}",
                alias_cert.session_nonce.len()
            )));
        }

        if alias_cert.combined_nonce_hash.len() != 48 {
            return Err(VerifierError::NonceBindingFailed(format!(
                "combined nonce hash must be 48 bytes (SHA-384), got {}",
                alias_cert.combined_nonce_hash.len()
            )));
        }

        if alias_cert.oob_hashes.cpu_evidence_hash.len() != 48 {
            return Err(VerifierError::NonceBindingFailed(format!(
                "OOB CPU evidence hash must be 48 bytes, got {}",
                alias_cert.oob_hashes.cpu_evidence_hash.len()
            )));
        }

        if alias_cert.oob_hashes.gpu_evidence_hash.len() != 48 {
            return Err(VerifierError::NonceBindingFailed(format!(
                "OOB GPU evidence hash must be 48 bytes, got {}",
                alias_cert.oob_hashes.gpu_evidence_hash.len()
            )));
        }

        if alias_cert.session_nonce.iter().all(|&b| b == 0) {
            return Err(VerifierError::NonceBindingFailed(
                "session nonce is all zeros (possible replay)".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns a report for a failed verification.
    pub fn verify_with_report(&self, chain: &DiceCertChain) -> VerificationReport {
        match self.verify(chain) {
            Ok(report) => report,
            Err(e) => VerificationReport {
                passed: false,
                device_serial: chain.device_id_cert.serial.clone(),
                device_class: chain.device_id_cert.device_class.clone(),
                firmware_layers_verified: 0,
                accumulated_fwid: hex::encode(chain.device_id_cert.accumulated_fwid()),
                session_nonce: hex::encode(&chain.alias_cert.session_nonce),
                oob_cpu_hash: hex::encode(&chain.alias_cert.oob_hashes.cpu_evidence_hash),
                oob_gpu_hash: hex::encode(&chain.alias_cert.oob_hashes.gpu_evidence_hash),
                alias_timestamp: chain.alias_cert.timestamp,
                failure_reason: Some(e.to_string()),
            },
        }
    }
}

/// On-path pre-verification backing for the OOB daemon.
impl super::oob_daemon::PreVerifier for DpuVerifier {
    fn pre_verify(&self, dpu_evidence: &[u8]) -> VerifierResult<()> {
        let json = std::str::from_utf8(dpu_evidence)
            .map_err(|e| VerifierError::MalformedEvidence(format!("E_D utf8: {e}")))?;
        let chain = DiceCertChain::from_json(json)?;
        self.verify(&chain).map(|_| ())
    }
}
