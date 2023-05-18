// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{
    mem,
    time::{Duration, SystemTime},
};

use anyhow::*;
use as_types::TeeEvidenceParsedClaim;
use async_trait::async_trait;
use intel_tee_quote_verification_rs::{
    sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};
use kbs_types::Attestation;
use scroll::Pread;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha384};

use self::types::sgx_quote3_t;

use super::Verifier;

#[allow(non_camel_case_types)]
mod types;

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
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_str::<SgxEvidence>(&attestation.tee_evidence)
            .context("Deserialize Quote failed.")?;

        let mut hasher = Sha384::new();
        hasher.update(&nonce);
        hasher.update(&attestation.tee_pubkey.k_mod);
        hasher.update(&attestation.tee_pubkey.k_exp);
        let mut hash_of_nonce_pubkey = hasher.finalize().to_vec();
        hash_of_nonce_pubkey.extend([0; 16]);

        debug!("TEE-Evidence<Sgx Occlum>: {:?}", &tee_evidence);

        verify_evidence(hash_of_nonce_pubkey, tee_evidence).await
    }
}

pub fn parse_sgx_quote(quote: &[u8]) -> Result<sgx_quote3_t> {
    let quote_body = &quote[..QUOTE_SIZE];
    quote_body
        .pread::<sgx_quote3_t>(0)
        .map_err(|e| anyhow!("Parse SGX quote failed: {:?}", e))
}

async fn verify_evidence(
    hash_of_nonce_pubkey: Vec<u8>,
    evidence: SgxEvidence,
) -> Result<TeeEvidenceParsedClaim> {
    let quote_bin = base64::decode(evidence.quote.clone())?;

    ecdsa_quote_verification(&quote_bin)
        .await
        .context("Evidence's identity verification error.")?;

    let quote = parse_sgx_quote(&quote_bin)?;
    if quote.report_body.report_data.d.to_vec() != hash_of_nonce_pubkey {
        bail!("HASH(nonce||pubkey) is different from that in SGX Quote");
    }

    generate_parsed_claims(quote)
}

async fn ecdsa_quote_verification(quote: &[u8]) -> Result<()> {
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
        Err(e) => bail!(
            "tee_get_quote_supplemental_data_size failed: {:#04x}",
            e as u32
        ),
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
            bail!(
                "Verification completed with Terminal result: {:x}",
                quote_verification_result as u32
            );
        }
    }

    Ok(())
}

fn generate_parsed_claims(quote: sgx_quote3_t) -> Result<TeeEvidenceParsedClaim> {
    // TODO: Add more claims
    // related issue: https://github.com/confidential-containers/enclave-cc/issues/121
    let mut claim_map = Map::new();

    claim_map.insert(
        "mr-signer".to_string(),
        Value::String(hex::encode(quote.report_body.mr_signer.m)),
    );
    claim_map.insert(
        "mr-enclave".to_string(),
        Value::String(hex::encode(quote.report_body.mr_enclave.m)),
    );

    Ok(Value::Object(claim_map) as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use std::fs;

    #[rstest]
    #[case("../test_data/occlum_quote.dat")]
    fn test_parse_sgx_quote(#[case] quote_dir: &str) {
        let quote_bin = fs::read(quote_dir).expect("read quote");
        let quote = parse_sgx_quote(&quote_bin);

        assert!(quote.is_ok());
        let parsed_quote = format!("{}", quote.unwrap());
        let _ = fs::write("../test_data/parse_sgx_quote_output.txt", parsed_quote);
    }

    #[ignore]
    #[rstest]
    #[tokio::test]
    #[case("../test_data/occlum_quote.dat")]
    async fn test_verify_sgx_quote(#[case] quote_dir: &str) {
        let quote_bin = fs::read(quote_dir).unwrap();
        let res = ecdsa_quote_verification(quote_bin.as_slice()).await;
        assert!(res.is_ok());
    }
}
