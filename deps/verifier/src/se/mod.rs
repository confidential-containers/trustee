// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use async_trait::async_trait;
use ibmse::SeVerifierImpl;
use log::warn;
use tokio::sync::OnceCell;

use crate::{InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};

pub mod ibmse;

static VERIFIER: OnceCell<SeVerifierImpl> = OnceCell::const_new();

#[derive(Debug, Default)]
pub struct SeVerifier;

#[async_trait]
impl Verifier for SeVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let se_verifier = VERIFIER
            .get_or_try_init(|| async { SeVerifierImpl::new() })
            .await?;
        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("IBM SE verifier does not support verify init data hash, will ignore the input `init_data_hash`.");
        }
        if let ReportData::Value(_) = expected_report_data {
            warn!("IBM SE verifier does not support verify report data hash, will ignore the input `report_data`.");
        }
        let claims = se_verifier.evaluate(evidence)?;
        Ok((claims, "cpu".to_string()))
    }

    async fn generate_supplemental_challenge(&self, _tee_parameters: String) -> Result<String> {
        let se_verifier = VERIFIER
            .get_or_try_init(|| async { SeVerifierImpl::new() })
            .await?;
        se_verifier
            .generate_supplemental_challenge(_tee_parameters)
            .await
    }
}
