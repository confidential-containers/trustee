// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    mem,
    time::{Duration, SystemTime},
};

use anyhow::*;
use async_trait::async_trait;
use base64::Engine;
use log::{debug, warn};
use scroll::Pread;
use serde::{Deserialize, Serialize};
use sgx_dcap_quoteverify_rs::{
    sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};

use crate::{regularize_data, InitDataHash, ReportData};

use self::types::sgx_quote3_t;

use super::{TeeEvidenceParsedClaim, Verifier};
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum SgxError {
    #[error("Deserialize Quote failed: {0}")]
    FailedtoDeserializeQuote(String),
    #[error("Sgx verifier error: {0}")]
    SgxVerifierErr(String),
    #[error("Parse SGX quote failed: {0}")]
    ParseSgxQuote(String),
    #[error("Evidence's identity verification error: {0}")]
    EvidenceIdentityVerification(String),
    #[error("REPORT_DATA is different from that in SGX Quote")]
    ReportDataMismatch,
    #[error("CONFIGID is different from that in SGX Quote")]
    ConfigIdMismatch,
    #[error(transparent)]
    Base64Err(#[from] base64::DecodeError),
    #[error(transparent)]
    TryfromSlice(#[from] std::array::TryFromSliceError),
    #[error("tee_get_quote_supplemental_data_size failed: {0}")]
    TeeGetQuoteSupplemtalData(String),
    #[error("Verification completed with Terminal result: {0}")]
    QuoteVerificationResult(String),
    #[error("generate_parsed_claims failed: {0}")]
    GenerateParsedClaims(String),
    #[error("ecdsa quote verification failed: {0}")]
    ECDSAQuoteVerification(String),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

#[async_trait]
impl Verifier for SgxVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_slice::<SgxEvidence>(evidence)
            .map_err(|err| SgxError::FailedtoDeserializeQuote(err.to_string()))?;

        debug!("TEE-Evidence<Sgx>: {:?}", &tee_evidence);

        verify_evidence(expected_report_data, expected_init_data_hash, tee_evidence)
            .await
            .map_err(|e| SgxError::SgxVerifierErr(e.to_string()).into())
    }
}

pub fn parse_sgx_quote(quote: &[u8]) -> Result<sgx_quote3_t, SgxError> {
    let quote_body = &quote[..QUOTE_SIZE];
    quote_body
        .pread::<sgx_quote3_t>(0)
        .map_err(|e| SgxError::ParseSgxQuote(e.to_string()))
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: SgxEvidence,
) -> Result<TeeEvidenceParsedClaim, SgxError> {
    let quote_bin = base64::engine::general_purpose::STANDARD.decode(evidence.quote)?;

    ecdsa_quote_verification(&quote_bin)
        .await
        .map_err(|e| SgxError::EvidenceIdentityVerification(e.to_string()))?;

    let quote = parse_sgx_quote(&quote_bin)?;
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "SGX");
        if expected_report_data != quote.report_body.report_data {
            return Err(SgxError::ReportDataMismatch);
        }
    }

    if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
        debug!("Check the binding of CONFIGID.");
        let expected_init_data_hash =
            regularize_data(expected_init_data_hash, 64, "CONFIGID", "SGX");
        if expected_init_data_hash != quote.report_body.config_id {
            return Err(SgxError::ConfigIdMismatch);
        }
    }

    claims::generate_parsed_claims(quote)
        .map_err(|err| SgxError::GenerateParsedClaims(err.to_string()))
}

async fn ecdsa_quote_verification(quote: &[u8]) -> Result<(), SgxError> {
    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

    match tee_get_supplemental_data_version_and_size(quote) {
        std::result::Result::Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                debug!("tee_get_quote_supplemental_data_version_and_size successfully returned.");
                debug!(
                    "Info: latest supplemental data major version: {}, minor version: {}, size: {}",
                    u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into()?),
                    u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into()?),
                    supp_size,
                );
                supp_data_desc.data_size = supp_size;
            } else {
                warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => return Err(SgxError::TeeGetQuoteSupplemtalData(format!("{:?}", e))),
    }

    // get collateral
    let _collateral = match tee_qv_get_collateral(quote) {
        std::result::Result::Ok(c) => {
            debug!("tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            warn!("tee_qv_get_collateral failed: {:#04x}", e as u32);
            None
        }
    };

    let p_collateral: Option<&[u8]> = None;

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) =
        tee_verify_quote(quote, p_collateral, current_time, None, p_supplemental_data)
            .map_err(|e| anyhow!("tee_verify_quote failed: {:#04x}", e as u32))?;

    debug!("tee_verify_quote successfully returned.");

    // check verification result
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            if collateral_expiration_status == 0 {
                debug!("Verification completed successfully.");
            } else {
                warn!("Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            warn!(
                "Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        _ => {
            return Err(SgxError::QuoteVerificationResult(format!(
                "{:?}",
                quote_verification_result as u32
            )))
        }
    }

    Ok(()).map_err(|err| SgxError::ECDSAQuoteVerification(err.to_string()))
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
