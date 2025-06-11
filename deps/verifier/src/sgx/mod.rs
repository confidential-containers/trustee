// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use log::debug;
use scroll::Pread;
use serde::{Deserialize, Serialize};

use self::types::sgx_quote3_t;
use super::{TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
use crate::intel_dcap::{ecdsa_quote_verification, extend_using_custom_claims};
use crate::{regularize_data, InitDataHash, ReportData};

#[allow(non_camel_case_types)]
mod types;

mod claims;
pub const QUOTE_SIZE: usize = 436;

#[derive(Debug, Serialize, Deserialize)]
struct SgxEvidence {
    // Base64 encoded SGX quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct SgxVerifier {}

#[async_trait]
impl Verifier for SgxVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tee_evidence =
            serde_json::from_value::<SgxEvidence>(evidence).context("Deserialize Quote failed.")?;

        debug!("TEE-Evidence<Sgx>: {:?}", &tee_evidence);

        let claims = verify_evidence(expected_report_data, expected_init_data_hash, tee_evidence)
            .await
            .map_err(|e| anyhow!("SGX Verifier: {:?}", e))?;

        Ok((claims, "cpu".to_string()))
    }
}

pub fn parse_sgx_quote(quote: &[u8]) -> Result<sgx_quote3_t> {
    let quote_body = &quote[..QUOTE_SIZE];
    quote_body
        .pread::<sgx_quote3_t>(0)
        .map_err(|e| anyhow!("Parse SGX quote failed: {:?}", e))
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: SgxEvidence,
) -> Result<TeeEvidenceParsedClaim> {
    if evidence.quote.is_empty() {
        bail!("SGX Quote is empty.");
    }

    let quote_bin = base64::engine::general_purpose::STANDARD.decode(evidence.quote)?;

    let custom_claims = ecdsa_quote_verification(&quote_bin)
        .await
        .context("Evidence's identity verification error.")?;

    let quote = parse_sgx_quote(&quote_bin)?;
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "SGX");
        if expected_report_data != quote.report_body.report_data {
            bail!("REPORT_DATA is different from that in SGX Quote");
        }
    }

    if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
        debug!("Check the binding of CONFIGID.");
        let expected_init_data_hash =
            regularize_data(expected_init_data_hash, 64, "CONFIGID", "SGX");
        if expected_init_data_hash != quote.report_body.config_id {
            bail!("CONFIGID is different from that in SGX Quote");
        }
    }

    let mut claim = claims::generate_parsed_claims(quote)?;
    extend_using_custom_claims(&mut claim, custom_claims)?;

    Ok(claim)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use std::fs;

    #[rstest]
    #[case("./test_data/occlum_quote.dat")]
    fn test_parse_sgx_quote(#[case] quote_dir: &str) {
        let quote_bin = fs::read(quote_dir).expect("read quote");
        let quote = parse_sgx_quote(&quote_bin);

        assert!(quote.is_ok());
        let parsed_quote = format!("{}", quote.unwrap());
        let _ = fs::write("./test_data/parse_sgx_quote_output.txt", parsed_quote);
    }

    #[ignore]
    #[rstest]
    #[tokio::test]
    #[case("./test_data/occlum_quote.dat")]
    async fn test_verify_sgx_quote(#[case] quote_dir: &str) {
        let quote_bin = fs::read(quote_dir).unwrap();
        let res = ecdsa_quote_verification(quote_bin.as_slice()).await;
        assert!(res.is_ok());
    }
}
