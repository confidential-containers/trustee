// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use async_trait::async_trait;
use ibmse::RealSeVerifier;
use log::warn;
use tokio::sync::OnceCell;

use crate::{InitDataHash, ReportData, TeeEvidenceParsedClaim, Verifier};

pub mod ibmse;

static ONCE: OnceCell<RealSeVerifier> = OnceCell::const_new();

#[derive(Debug, Default)]
pub struct SeVerifier;

#[async_trait]
impl Verifier for SeVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        _expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let se_verifier = ONCE
            .get_or_try_init(|| async { RealSeVerifier::new() })
            .await?;
        warn!("IBM SE does not support initdata.");
        se_verifier.evaluate(evidence)
    }

    async fn generate_supplemental_challenge(
        &self,
        _tee_parameters: String,
    ) -> Result<String> {
        let se_verifier = ONCE
            .get_or_try_init(|| async { RealSeVerifier::new() })
            .await?;
        se_verifier.generate_supplemental_challenge(_tee_parameters).await
    }
}
