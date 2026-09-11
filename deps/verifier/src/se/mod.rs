// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use ibmse::SeVerifierImpl;
use serde::Deserialize;
use tokio::sync::{OnceCell, SetError};
use tracing::{instrument, warn};

use crate::{InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};

pub mod ibmse;

static VERIFIER: OnceCell<SeVerifierImpl> = OnceCell::const_new();

const DEFAULT_FIRMWARE_VERIFY_URL: &str =
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
        // `new()` is called for every request, but the static VERIFIER is only populated
        // once; the config of the first call wins and later calls reuse it.
        //
        // Fast path: already initialized, skip building a SeVerifierImpl (which reads
        // the key files from disk). This check is not atomic with the `set()` below.
        if VERIFIER.initialized() {
            return Ok(Self);
        }

        // Populate the static VERIFIER with config at construction time, before any
        // request arrives. get_or_try_init() in evaluate() will retrieve this value
        // directly
        match VERIFIER.set(SeVerifierImpl::new(config)?) {
            Ok(()) => Ok(Self),
            // Race: another concurrent caller passed the check above and populated the
            // cell before our `set()`. The verifier is initialized and usable, so this
            // is not an error. The early return above cannot cover this case.
            Err(SetError::AlreadyInitializedError(_)) => Ok(Self),
            // Any other failure (e.g. another task is still initializing the cell) is
            // reported to the caller.
            Err(e) => Err(anyhow!("failed to set IBM SE verifier: {e}")),
        }
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
            warn!(
                "IBM SE verifier does not support verify init data hash, will ignore the input `init_data_hash`."
            );
        }
        let claims = se_verifier.evaluate(evidence, expected_report_data)?;
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
