// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! # NVIDIA DPU Verifier
//!
//! This verifier validates attestation evidence from NVIDIA BlueField DPUs
//! using the TCG DICE (Device Identifier Composition Engine) standard.
//!
//! ## Verification Flow
//!
//! 1. Parse `DpuEvidence` from the attester (versioned multi-device format)
//! 2. Verify DICE certificate chain: Root CA → DeviceID → Alias (in `verifier.rs`)
//! 3. Verify report_data freshness binding via alias-key ECDSA signature (in this module's `evaluate()`)
//! 4. Extract TCB claims (FWID measurements) from DICE certificates
//!
//! ## Evidence Format
//!
//! The attester produces a versioned JSON object containing per-device evidence:
//! - `version`: Evidence format version (integer)
//! - `devices`: Array of per-device evidence entries, where cert fields
//!   (`alias_cert`, `device_id_cert`) are base64-encoded DER X.509 certificates

pub mod dice;
pub mod verifier;

pub use verifier::{NvidiaDpuVerifier, NvidiaDpuVerifierConfig, VerificationReport};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use dice::{AliasCert, DeviceIdCert, DiceCertChain};
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use serde_with::{base64::Base64, serde_as};
use tracing::{debug, info};

use crate::{InitDataHash, ReportData, TeeEvidenceParsedClaim};

/// TEE class identifier for NVIDIA DPU DICE attestation.
pub const TEE_CLASS_NVIDIA_DPU: &str = "nvidia-dpu";

/// Top-level evidence structure received from the NVIDIA DPU attester.
#[derive(Debug, Deserialize)]
pub struct DpuEvidence {
    /// Evidence format version
    pub version: u32,
    /// Per-device attestation evidence
    pub devices: Vec<DpuDeviceEvidence>,
}

/// Evidence from a single DPU device.
#[serde_as]
#[derive(Debug, Deserialize)]
pub struct DpuDeviceEvidence {
    /// Device architecture identifier (e.g. "bluefield3")
    pub architecture: String,
    /// DER-encoded X.509 DICE Alias certificate
    #[serde_as(as = "Base64")]
    pub alias_cert: Vec<u8>,
    /// DER-encoded X.509 DICE DeviceID certificate
    #[serde_as(as = "Base64")]
    pub device_id_cert: Vec<u8>,
    /// ECDSA P-384 signature of report_data using alias private key
    #[serde_as(as = "Base64")]
    pub report_data_signature: Vec<u8>,
}

/// Verify report_data freshness binding via alias key signature.
///
/// Uses the alias public key already extracted and verified during DICE chain
/// validation (step 3), ensuring we use the authenticated key rather than
/// re-extracting from raw bytes.
fn verify_report_data_binding(
    alias_pubkey: &p384::PublicKey,
    report_data_signature: &[u8],
    expected_report_data: &[u8],
) -> Result<()> {
    // Signature is mandatory — reject unsigned evidence to prevent replay attacks
    if report_data_signature.is_empty() {
        bail!("report_data_signature is required — unsigned evidence rejected to prevent replay attacks");
    }

    let verifying_key = VerifyingKey::from(alias_pubkey);
    let signature = Signature::from_der(report_data_signature)
        .or_else(|_| Signature::from_bytes(report_data_signature.into()))
        .context("invalid signature format (tried DER and fixed-width r||s)")?;

    verifying_key
        .verify(expected_report_data, &signature)
        .context("report_data signature verification failed - freshness binding broken")?;

    Ok(())
}

#[async_trait]
impl crate::Verifier for NvidiaDpuVerifier {
    async fn evaluate(
        &self,
        evidence: crate::TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, String)>> {
        info!("Initializing NVIDIA DPU DICE verifier");
        debug!("NVIDIA DPU verifier: evaluating DICE evidence");

        // (1) Parse the DPU evidence from the attester JSON.
        let dpu_evidence: DpuEvidence =
            serde_json::from_value(evidence).context("Failed to parse NVIDIA DPU evidence")?;

        // (2) Assert exactly one device and get it.
        anyhow::ensure!(
            dpu_evidence.devices.len() == 1,
            "Expected exactly one device in evidence, got {}",
            dpu_evidence.devices.len()
        );
        let device = &dpu_evidence.devices[0];

        // (3) Parse DICE certificates from DER-encoded X.509.
        let device_id_cert = DeviceIdCert::from_der(&device.device_id_cert)
            .context("Failed to parse DeviceID X.509 DER certificate")?;
        let alias_cert = AliasCert::from_der(&device.alias_cert)
            .context("Failed to parse Alias X.509 DER certificate")?;
        let chain = DiceCertChain {
            device_id_cert,
            alias_cert,
        };

        // (4) Verify DICE certificate chain (signatures, temporal validity).
        self.verify_cert_chain(&chain)
            .context("NVIDIA DPU DICE chain verification failed")?;
        let report = self.generate_report(&chain);

        // (5) Enforce report_data binding via alias-key signature verification.
        if let ReportData::Value(expected) = expected_report_data {
            verify_report_data_binding(
                &chain.alias_cert.public_key,
                &device.report_data_signature,
                expected,
            )?;
        }

        // (6) init_data is not supported for single-chain DICE.
        if let InitDataHash::Value(_expected) = expected_init_data_hash {
            debug!("NVIDIA DPU verifier: init_data is not supported");
        }

        // (7) Build the parsed claims.
        let claims =
            serde_json::to_value(&report).context("Failed to serialize NVIDIA DPU report")?;

        info!("NVIDIA DPU verifier: evidence verified successfully");
        Ok(vec![(claims, TEE_CLASS_NVIDIA_DPU.to_string())])
    }
}
