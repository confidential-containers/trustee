// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! DPU DICE certificate chain verifier for the Tri-Secure tri-core attestation protocol.
//!
//! This module implements the DPU-side verification logic described in §5.4 of
//! the Tri-Secure paper. It validates the DPU's DICE certificate chain as part
//! of the Trustee attestation service.
//!
//! ## DICE Verification Flow
//!
//! 1. Verify the Alias certificate signature against the DeviceID public key (ECDSA P-384)
//! 2. Verify the DeviceID certificate signature against the manufacturer's Root CA
//! 3. Extract FWID (Firmware ID) measurements from each certificate layer
//! 4. Compare FWIDs against reference values in RVPS (Reference Value Provider Service)
//! 5. Verify nonce binding to ensure the evidence is fresh and session-bound

pub mod binder;
pub mod crypto;
pub mod dice;
pub mod error;
pub mod oob_daemon;
pub mod rvps;
pub mod split_key;
pub mod verifier;

pub use binder::{BindingNonce, ChipEvidence, ChipKind, TriCoreBinder, TriCoreBundle};
pub use dice::{AliasCert, DeviceIdCert, DiceCertChain, FirmwareLayer};
pub use error::{VerifierError as DpuVerifierError, VerifierResult as DpuVerifierResult};
pub use oob_daemon::{LoopbackRshim, OobDaemon, OobReport, RshimChannel};
pub use rvps::{InMemoryRvps, ReferenceValue, RvpsClient};
pub use split_key::{GuestChannel, KeyShare, SplitKeyReceiver};
pub use verifier::{DpuVerifier, DpuVerifierConfig, VerificationReport};

use anyhow::Result;
use async_trait::async_trait;
use tracing::{debug, info};

use crate::{InitDataHash, ReportData, TeeEvidenceParsedClaim};

/// TEE class identifier for DPU DICE attestation.
pub const TEE_CLASS_DPU: &str = "dpu";

/// Constructor for use in `to_verifier()` dispatch.
impl DpuVerifier {
    /// Creates a new DpuVerifier with default configuration.
    ///
    /// Uses a placeholder Root CA key for development. In production,
    /// the Root CA key would be provisioned from a secure source.
    pub fn new() -> Result<Self> {
        info!("Initializing DPU DICE verifier");
        let config = DpuVerifierConfig::default();
        let rvps_client = Box::new(InMemoryRvps::new());
        Ok(Self::with_config(config, rvps_client))
    }
}

#[async_trait]
impl crate::Verifier for DpuVerifier {
    async fn evaluate(
        &self,
        evidence: crate::TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, String)>> {
        debug!("DPU verifier: evaluating DICE evidence");

        // (1) Parse the DPU's DICE certificate chain from the evidence JSON.
        let chain: DiceCertChain = serde_json::from_value(evidence.clone())
            .map_err(|e| anyhow::anyhow!("Failed to parse DPU DICE evidence: {}", e))?;

        // (2) Run the DPU DICE chain verification (signatures, RVPS, freshness,
        //     nonce binding). Any failure short-circuits to Err.
        let report = self.verify(&chain)
            .map_err(|e| anyhow::anyhow!("DPU DICE verification failed: {}", e))?;

        // (3a) Enforce the report_data binding: the DICE session nonce must equal
        //      the challenge the AS expects.
        if let ReportData::Value(expected) = expected_report_data {
            if chain.alias_cert.session_nonce.as_slice() != *expected {
                anyhow::bail!(
                    "DPU report_data mismatch: evidence bound to a different nonce \
                     (expected {} bytes, evidence carries {} bytes)",
                    expected.len(),
                    chain.alias_cert.session_nonce.len()
                );
            }
        }

        // (3b) Enforce the init-data hash binding against the tri-core combined
        //      nonce hash H(N_C || N_G || N_D).
        if let InitDataHash::Value(expected) = expected_init_data_hash {
            if chain.alias_cert.combined_nonce_hash.as_slice() != *expected {
                anyhow::bail!(
                    "DPU init_data_hash mismatch against combined tri-core nonce hash"
                );
            }
        }

        // (4) Build the parsed claims and tag the new dpu tee_class.
        let mut claims = serde_json::to_value(&report)
            .map_err(|e| anyhow::anyhow!("Failed to serialize DPU report: {}", e))?;
        if let serde_json::Value::Object(map) = &mut claims {
            map.insert(
                "tee_class".to_string(),
                serde_json::Value::String(TEE_CLASS_DPU.to_string()),
            );
        }

        info!("DPU verifier: evidence verified successfully");
        Ok(vec![(claims, TEE_CLASS_DPU.to_string())])
    }
}
