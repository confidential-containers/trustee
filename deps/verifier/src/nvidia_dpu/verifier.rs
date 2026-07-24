// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Core NVIDIA DPU DICE certificate chain verifier.
//!
//! Implements the verification logic for NVIDIA DPU hardware attestation:
//!
//! 1. Verify Alias cert signature against DeviceID public key (ECDSA P-384)
//! 2. Verify DeviceID cert signature against manufacturer Root CA
//! 3. Check certificate temporal validity
//! 4. Extract FWID measurements from each firmware layer
//!
//! Note: report_data freshness binding is handled in the parent module (`mod.rs`)
//! via `verify_report_data_binding()`, not in this file.

use anyhow::{anyhow, bail, Context, Result};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p384::PublicKey;
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::debug;

use super::dice::DiceCertChain;

/// Configuration for the NVIDIA DPU verifier (loaded from AS config.json).
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct NvidiaDpuVerifierConfig {
    /// PEM file path of the manufacturer Root CA certificate.
    /// The certificate's SubjectPublicKeyInfo is extracted as the P-384 trust anchor
    /// used to verify the DeviceID certificate signature.
    pub root_ca_cert_path: String,
    /// Maximum allowed certificate age in seconds (default: 3600).
    #[serde(default = "default_max_cert_age")]
    pub max_cert_age_secs: u64,
}

fn default_max_cert_age() -> u64 {
    3600
}

/// Detailed verification report (only represents successful verification).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Device serial number
    pub device_serial: String,
    /// Device class
    pub device_class: String,
    /// Number of firmware layers present
    pub firmware_layers_count: usize,
    /// Accumulated FWID (SHA-384)
    pub accumulated_fwid: String,
    /// Alias certificate timestamp
    pub alias_timestamp: u64,
}

/// The main NVIDIA DPU verifier.
pub struct NvidiaDpuVerifier {
    root_ca_public_key: PublicKey,
    max_cert_age_secs: u64,
}

impl NvidiaDpuVerifier {
    /// Creates a new verifier from config, loading the Root CA certificate from disk.
    pub fn new(config: NvidiaDpuVerifierConfig) -> Result<Self> {
        let pem_bytes = fs::read(&config.root_ca_cert_path).with_context(|| {
            format!("Failed to read root CA cert: {}", config.root_ca_cert_path)
        })?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&pem_bytes)
            .map_err(|e| anyhow!("PEM parse error: {e}"))?;
        let cert = pem
            .parse_x509()
            .context("Failed to parse X.509 root CA certificate")?;
        let root_ca_public_key = super::dice::extract_p384_pubkey(&cert)?;
        Ok(Self {
            root_ca_public_key,
            max_cert_age_secs: config.max_cert_age_secs,
        })
    }

    /// Verify DICE certificate chain trust: Root CA → DeviceID → Alias.
    pub fn verify_cert_chain(&self, chain: &DiceCertChain) -> Result<()> {
        // Step 1: Verify Alias cert signed by DeviceID key
        let device_id_vk = VerifyingKey::from(&chain.device_id_cert.public_key);
        let alias_sig = Signature::from_der(&chain.alias_cert.device_id_signature)
            .context("Alias cert: invalid signature encoding")?;
        device_id_vk
            .verify(&chain.alias_cert.tbs_raw, &alias_sig)
            .context("Alias cert: signature verification failed")?;

        // Step 2: Verify DeviceID cert signed by Root CA
        let root_vk = VerifyingKey::from(&self.root_ca_public_key);
        let did_sig = Signature::from_der(&chain.device_id_cert.root_ca_signature)
            .context("DeviceID cert: invalid signature encoding")?;
        root_vk
            .verify(&chain.device_id_cert.tbs_raw, &did_sig)
            .context("DeviceID cert: Root CA signature verification failed")?;

        // Step 3: Temporal validity
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock error")?
            .as_secs();

        if !chain.device_id_cert.is_valid_at(now) {
            bail!("DeviceID certificate has expired or is not yet valid");
        }

        if now < chain.alias_cert.timestamp
            || (now - chain.alias_cert.timestamp) > self.max_cert_age_secs
        {
            bail!(
                "Alias cert age {}s exceeds max {}s",
                now.saturating_sub(chain.alias_cert.timestamp),
                self.max_cert_age_secs
            );
        }

        debug!(
            "NVIDIA DPU verifier: DICE chain verified ({} firmware layers)",
            chain.device_id_cert.firmware_layers.len()
        );

        Ok(())
    }

    /// Extract TCB claims from a verified DICE chain (pure data extraction).
    pub fn generate_report(&self, chain: &DiceCertChain) -> VerificationReport {
        let firmware_layers_count = chain.device_id_cert.firmware_layers.len();
        VerificationReport {
            device_serial: chain.device_id_cert.serial.clone(),
            device_class: chain.device_id_cert.device_class.clone(),
            firmware_layers_count,
            accumulated_fwid: hex::encode(chain.device_id_cert.accumulated_fwid()),
            alias_timestamp: chain.alias_cert.timestamp,
        }
    }
}
