// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use async_trait::async_trait;
use ibmse::SeVerifierImpl;
use serde::Deserialize;
use tokio::sync::OnceCell;
use tracing::{instrument, warn};

use crate::{InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};

pub mod ibmse;

static VERIFIER: OnceCell<SeVerifierImpl> = OnceCell::const_new();

pub(super) const DEFAULT_FIRMWARE_VERIFY_URL: &str =
    "https://esupport.ibm.com/eccedge/ent/z/hmrs/firmware/attestation/v1/verify";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SeVerifierConfig {
    #[serde(default)]
    pub enable_firmware_verification: bool,

    #[serde(default = "default_firmware_verify_url")]
    pub firmware_verify_url: String,
}

fn default_firmware_verify_url() -> String {
    DEFAULT_FIRMWARE_VERIFY_URL.to_string()
}

impl Default for SeVerifierConfig {
    fn default() -> Self {
        Self {
            enable_firmware_verification: false,
            firmware_verify_url: DEFAULT_FIRMWARE_VERIFY_URL.to_string(),
        }
    }
}

#[derive(Debug, Default)]
pub struct SeVerifier;

impl SeVerifier {
    pub fn new(config: Option<SeVerifierConfig>) -> Result<Self> {
        // Populate the static VERIFIER with config at construction time, before any
        // request arrives. get_or_try_init() in evaluate() will retrieve this value
        // directly
        let _ = VERIFIER.set(SeVerifierImpl::new(config)?);
        Ok(Self)
    }
}

#[async_trait]
impl Verifier for SeVerifier {
    #[instrument(skip_all, name = "IBM SE")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let se_verifier = VERIFIER
            .get_or_try_init(|| async { SeVerifierImpl::new(None) })
            .await?;
        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("IBM SE verifier does not support verify init data hash, will ignore the input `init_data_hash`.");
        }
        let claims = se_verifier.evaluate(evidence, expected_report_data).await?;
        Ok(vec![(claims, "cpu".to_string())])
    }

    async fn generate_supplemental_challenge(&self, tee_parameters: String) -> Result<String> {
        let se_verifier = VERIFIER
            .get_or_try_init(|| async { SeVerifierImpl::new(None) })
            .await?;
        se_verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
    }
}
