// Copyright (c) 2023 by Intel.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    attestation::backend::{generic_generate_challenge, make_nonce, Attest},
    token::{jwk::JwkAttestationTokenVerifier, AttestationTokenVerifierConfig},
};
use anyhow::*;
use async_trait::async_trait;
use az_cvm_vtpm::hcl::HclReport;
use base64::{engine::general_purpose::STANDARD, Engine};
use derivative::Derivative;
use kbs_types::Challenge;
use kbs_types::{Attestation, Tee};
use reqwest::header::{ACCEPT, CONTENT_TYPE, USER_AGENT};
use serde::{Deserialize, Serialize};
use serde_json::{from_value, json};
use std::result::Result::Ok;
use strum::{AsRefStr, Display, EnumString};

const SUPPORTED_HASH_ALGORITHMS_JSON_KEY: &str = "supported-hash-algorithms";
const SELECTED_HASH_ALGORITHM_JSON_KEY: &str = "selected-hash-algorithm";

const ERR_NO_TEE_ALGOS: &str = "ITA: TEE does not support any hash algorithms";
const ERR_INVALID_TEE: &str = "ITA: Unknown TEE specified";

const BASE_AS_ADDR: &str = "/appraisal/v1/attest";
const AZURE_TDXVM_ADDR: &str = "/appraisal/v1/attest/azure/tdxvm";

const TRUSTEE_USER_AGENT: &str = "Confidential-containers-trustee";

#[derive(Display, EnumString, AsRefStr)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    Sha256,

    #[strum(ascii_case_insensitive)]
    Sha384,

    #[strum(ascii_case_insensitive)]
    Sha512,
}

#[derive(Deserialize, Debug)]
struct ItaTeeEvidence {
    #[serde(skip)]
    _cc_eventlog: Option<String>,
    quote: String,
}

#[derive(Deserialize, Debug)]
struct AzItaTeeEvidence {
    hcl_report: Vec<u8>,
    td_quote: Vec<u8>,
}

#[derive(Serialize, Debug)]
struct AttestReqData {
    quote: String,
    runtime_data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_data: Option<String>,
    policy_ids: Vec<String>,
    policy_must_match: bool,
}

#[derive(Deserialize, Debug)]
struct AttestRespData {
    token: String,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    error: String,
}

#[derive(Clone, Derivative, Deserialize, PartialEq, Default)]
#[derivative(Debug)]
pub struct IntelTrustAuthorityConfig {
    pub base_url: String,
    #[derivative(Debug = "ignore")]
    pub api_key: String,
    pub certs_file: String,
    pub allow_unmatched_policy: Option<bool>,
    pub policy_ids: Vec<String>,
}

pub struct IntelTrustAuthority {
    config: IntelTrustAuthorityConfig,
    token_verifier: JwkAttestationTokenVerifier,
}

#[async_trait]
impl Attest for IntelTrustAuthority {
    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        // get quote
        let attestation = serde_json::from_str::<Attestation>(attestation)
            .context("Failed to deserialize Attestation request")?;

        let runtime_data = json!({
            "tee-pubkey": attestation.tee_pubkey,
            "nonce": nonce,
        })
        .to_string();

        let policy_ids = self.config.policy_ids.clone();

        let policy_must_match = match policy_ids.is_empty() {
            true => false,
            false => !self.config.allow_unmatched_policy.unwrap_or_default(),
        };

        // construct attest request data and attestation url
        let (req_data, att_url) = match tee {
            Tee::AzTdxVtpm => {
                let att_url = format!("{}{AZURE_TDXVM_ADDR}", &self.config.base_url);

                let evidence = from_value::<AzItaTeeEvidence>(attestation.tee_evidence)
                    .context(format!("Failed to deserialize TEE: {:?} Evidence", &tee))?;

                let hcl_report = HclReport::new(evidence.hcl_report.clone())?;

                let req_data = AttestReqData {
                    quote: STANDARD.encode(evidence.td_quote),
                    runtime_data: STANDARD.encode(hcl_report.var_data()),
                    user_data: Some(STANDARD.encode(runtime_data)),
                    policy_ids,
                    policy_must_match,
                };

                (req_data, att_url)
            }
            Tee::Tdx | Tee::Sgx => {
                let att_url = format!("{}{BASE_AS_ADDR}", &self.config.base_url);

                let evidence = from_value::<ItaTeeEvidence>(attestation.tee_evidence)
                    .context(format!("Failed to deserialize TEE: {:?} Evidence", &tee))?;

                let req_data = AttestReqData {
                    quote: evidence.quote,
                    runtime_data: STANDARD.encode(runtime_data),
                    user_data: None,
                    policy_ids,
                    policy_must_match,
                };

                (req_data, att_url)
            }
            _ => {
                bail!("Intel Trust Authority: TEE {tee:?} is not supported.");
            }
        };

        let attest_req_body = serde_json::to_string(&req_data)
            .context("Failed to serialize attestation request body")?;

        // send attest request
        log::info!("POST attestation request ...");
        log::debug!("Attestation URL: {:?}", &att_url);

        let user_agent = format!(
            "{TRUSTEE_USER_AGENT} {}/{}",
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION")
        );

        let client = reqwest::Client::new();
        let resp = client
            .post(att_url)
            .header(USER_AGENT, user_agent)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header("x-api-key", &self.config.api_key)
            .body(attest_req_body)
            .send()
            .await
            .context("Failed to POST attestation HTTP request")?;

        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            let body = resp
                .json::<ErrorResponse>()
                .await
                .context("Failed to deserialize attestation error response");

            // Only inspect the body if there is one.
            match body {
                Ok(body) => bail!(
                    "Attestation request failed: response status={}, message={}",
                    status,
                    body.error
                ),
                _ => bail!("Attestation request failed: response status={}", status),
            }
        }
        let resp_data = resp
            .json::<AttestRespData>()
            .await
            .context("Failed to deserialize attestation response")?;

        let _token = self
            .token_verifier
            .verify(resp_data.token.clone())
            .await
            .context("Failed to verify attestation token")?;

        Ok(resp_data.token.clone())
    }

    async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: serde_json::Value,
    ) -> Result<Challenge> {
        log::debug!("ITA: generate_challenge: tee: {tee:?}, tee_parameters: {tee_parameters:?}");

        if tee_parameters.is_null() {
            log::debug!(
                "ITA: generate_challenge: no TEE parameters so falling back to legacy behaviour"
            );

            return generic_generate_challenge(tee, tee_parameters).await;
        }

        let mut supported_hash_algorithms = vec![];

        let Some(hash_algorithms_found) = tee_parameters.get(SUPPORTED_HASH_ALGORITHMS_JSON_KEY)
        else {
            log::info!("ITA: generate_challenge: no TEE hash parameters, so falling back to legacy behaviour");

            return generic_generate_challenge(tee, tee_parameters).await;
        };

        let Some(algorithms) = hash_algorithms_found.as_array() else {
            return Err(anyhow!(
                "ITA: expected array, found {hash_algorithms_found:?}"
            ));
        };

        let hash_algorithms: Vec<String> = algorithms
            .iter()
            .filter_map(|s| Some(s.as_str()?.to_lowercase()))
            .collect();

        supported_hash_algorithms.append(&mut hash_algorithms.clone());

        if supported_hash_algorithms.is_empty() {
            log::debug!("ITA: generate_challenge: no tee algorithms available");

            bail!(ERR_NO_TEE_ALGOS);
        }

        log::debug!(
            "ITA: generate_challenge: supported_hash_algorithms: {supported_hash_algorithms:?}"
        );

        let hash_algorithm: String = match tee {
            Tee::Sgx | Tee::AzTdxVtpm => {
                let needed_algorithm = HashAlgorithm::Sha256.as_ref().to_string().to_lowercase();

                if supported_hash_algorithms.contains(&needed_algorithm) {
                    needed_algorithm
                } else {
                    bail!("ITA: SGX TEE does not support {needed_algorithm}");
                }
            }
            Tee::Tdx => {
                let needed_algorithm = HashAlgorithm::Sha512.as_ref().to_string().to_lowercase();

                if supported_hash_algorithms.contains(&needed_algorithm) {
                    needed_algorithm
                } else {
                    bail!("ITA: TDX TEE does not support {needed_algorithm}");
                }
            }
            _ => bail!(ERR_INVALID_TEE),
        };

        let extra_params = json!({
            SELECTED_HASH_ALGORITHM_JSON_KEY: hash_algorithm,
        });

        let nonce = make_nonce().await?;

        Ok(Challenge {
            nonce,
            extra_params,
        })
    }
}

impl IntelTrustAuthority {
    pub async fn new(config: IntelTrustAuthorityConfig) -> Result<Self> {
        let token_verifier = JwkAttestationTokenVerifier::new(&AttestationTokenVerifierConfig {
            extra_teekey_paths: vec![],
            trusted_certs_paths: vec![],
            trusted_jwk_sets: vec![config.certs_file.clone()],
            insecure_key: true,
        })
        .await
        .context("Failed to initialize token verifier")?;

        Ok(Self {
            config: config.clone(),
            token_verifier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::*;
    use serde_json::Value;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // Generate the contents for an ITA certificates file and return it as
    // a JSON string.
    fn create_certs_file_json_string() -> String {
        let data = json!({ "keys": [
        {
            "alg": "PS384",
            "e": "AQAB",
            "kid": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "kty": "RSA",
            "n": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "x5c": [
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          ]
        },
        {
            "alg": "RS256",
            "e": "AQAB",
            "kid": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "kty": "RSA",
            "n": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "x5c": [
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
          ]
        }]}).to_string();

        data
    }

    #[rstest]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!({}),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: "".into()
        })
    )]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!(null),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: "".into()
        })
    )]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!(""),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: "".into()
        })
    )]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: []}),
        Err(anyhow!(ERR_NO_TEE_ALGOS))
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!({}),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: "".into()
        })
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!(null),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: "".into()
        })
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!(""),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: "".into()
        })
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: []}),
        Err(anyhow!(ERR_NO_TEE_ALGOS))
    )]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: [HashAlgorithm::Sha256.to_string()]}),
        Err(anyhow!("ITA: TDX TEE does not support sha512"))
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: [HashAlgorithm::Sha512.to_string()]}),
        Err(anyhow!("ITA: SGX TEE does not support sha256"))
    )]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: [HashAlgorithm::Sha512.to_string()]}),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: json!({SELECTED_HASH_ALGORITHM_JSON_KEY: HashAlgorithm::Sha512.to_string()})})
    )]
    #[tokio::test]
    #[case(
        Tee::Tdx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: [HashAlgorithm::Sha256.to_string(), HashAlgorithm::Sha512.to_string()]}),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: json!({SELECTED_HASH_ALGORITHM_JSON_KEY: HashAlgorithm::Sha512.to_string()})})
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: [HashAlgorithm::Sha256.to_string()]}),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: json!({SELECTED_HASH_ALGORITHM_JSON_KEY: HashAlgorithm::Sha256.to_string()})})
    )]
    #[tokio::test]
    #[case(
        Tee::Sgx,
        json!({SUPPORTED_HASH_ALGORITHMS_JSON_KEY: [HashAlgorithm::Sha256.to_string(), HashAlgorithm::Sha512.to_string()]}),
        Ok(Challenge{
            nonce: "".into(),
            extra_params: json!({SELECTED_HASH_ALGORITHM_JSON_KEY: HashAlgorithm::Sha256.to_string()})})
    )]
    async fn test_ita_generate_challenge(
        #[case] tee: Tee,
        #[case] params: Value,
        #[case] expected_result: Result<Challenge>,
    ) {
        let mut file = NamedTempFile::new().unwrap();
        let certs_file = "file://".to_owned() + &file.path().display().to_string();

        let json = create_certs_file_json_string();

        file.write_all(json.as_bytes())
            .expect("failed to write certs file data");

        let cfg = IntelTrustAuthorityConfig {
            base_url: "".into(),
            api_key: "".into(),
            certs_file,
            allow_unmatched_policy: None,
            policy_ids: vec![],
        };

        let msg = format!(
            "test: certs file json: {json:?}, cfg: {cfg:?}, tee: {tee:?}, params: {params:?}, expected result: {expected_result:?}"
        );

        let ita = IntelTrustAuthority::new(cfg).await.unwrap();

        let actual_result = ita.generate_challenge(tee, params).await;

        let msg = format!("{msg}, actual result: {actual_result:?}");

        if std::env::var("DEBUG").is_ok() {
            println!("DEBUG: {}", msg);
        }

        // Note: for now we simply check for error, not the type of error returned.
        if expected_result.is_err() {
            assert!(actual_result.is_err(), "{msg}");
            return;
        }

        // Only compare the params as the nonce will have a generated value.
        let expected_extra_params = expected_result
            .unwrap()
            .extra_params
            .to_string()
            .to_lowercase();
        let actual_extra_params = actual_result
            .unwrap()
            .extra_params
            .to_string()
            .to_lowercase();

        assert_eq!(actual_extra_params, expected_extra_params, "{}", msg);
    }
}
