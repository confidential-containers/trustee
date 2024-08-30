// Copyright (c) 2023 by Intel.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::Attest;
use crate::token::{
    jwk::JwkAttestationTokenVerifier, AttestationTokenVerifier, AttestationTokenVerifierConfig,
    AttestationTokenVerifierType,
};
use anyhow::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::{Attestation, Tee};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize, Debug)]
struct IntelTrustAuthorityTeeEvidence {
    #[serde(skip)]
    _cc_eventlog: Option<String>,
    quote: String,
}

#[derive(Serialize, Debug)]
struct AttestReqData {
    quote: String,
    runtime_data: String,
}

#[derive(Deserialize, Debug)]
struct AttestRespData {
    token: String,
}

#[derive(Deserialize, Debug)]
struct Claims {
    policy_ids_unmatched: Option<Vec<serde_json::Value>>,
}

#[derive(Deserialize, Debug)]
struct ErrorResponse {
    error: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct IntelTrustAuthorityConfig {
    pub base_url: String,
    pub api_key: String,
    pub certs_file: String,
    pub allow_unmatched_policy: Option<bool>,
}

pub struct IntelTrustAuthority {
    config: IntelTrustAuthorityConfig,
    token_verifier: JwkAttestationTokenVerifier,
}

#[async_trait]
impl Attest for IntelTrustAuthority {
    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        if tee != Tee::Tdx && tee != Tee::Sgx {
            bail!("Intel Trust Authority: TEE {tee:?} is not supported.");
        }
        // get quote
        let attestation = serde_json::from_str::<Attestation>(attestation)
            .map_err(|e| anyhow!("Deserialize Attestation failed: {:?}", e))?;
        let evidence =
            serde_json::from_value::<IntelTrustAuthorityTeeEvidence>(attestation.tee_evidence)
                .map_err(|e| anyhow!("Deserialize supported TEE Evidence failed: {:?}", e))?;

        let runtime_data = json!({
            "tee-pubkey": attestation.tee_pubkey,
            "nonce": nonce,
        })
        .to_string();

        // construct attest request data
        let req_data = AttestReqData {
            quote: evidence.quote,
            runtime_data: STANDARD.encode(runtime_data),
        };

        let attest_req_body = serde_json::to_string(&req_data)
            .map_err(|e| anyhow!("Serialize attestation request body failed: {:?}", e))?;

        // send attest request
        log::info!("post attestation request ...");
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/appraisal/v1/attest", &self.config.base_url))
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header("x-api-key", &self.config.api_key)
            .body(attest_req_body)
            .send()
            .await
            .map_err(|e| anyhow!("Post attestation request failed: {:?}", e))?;

        let status = resp.status();
        if status != reqwest::StatusCode::OK {
            let body = resp
                .json::<ErrorResponse>()
                .await
                .map_err(|e| anyhow!("Deserialize error response failed: {:?}", e))?;
            bail!(
                "Attestation request failed: response status={}, message={}",
                status,
                body.error
            );
        }
        let resp_data = resp
            .json::<AttestRespData>()
            .await
            .context("Failed to deserialize attestation response")?;

        let token = self
            .token_verifier
            .verify(resp_data.token.clone())
            .await
            .context("Failed to verify attestation token")?;

        let claims = serde_json::from_str::<Claims>(&token)
            .context("Failed to deserialize attestation token claims")?;

        // check unmatched policy
        let allow = self.config.allow_unmatched_policy.unwrap_or(false);
        if !allow && claims.policy_ids_unmatched.is_some() {
            bail!("Evidence doesn't match policy");
        }

        Ok(resp_data.token.clone())
    }
}

impl IntelTrustAuthority {
    pub async fn new(config: IntelTrustAuthorityConfig) -> Result<Self> {
        let token_verifier = JwkAttestationTokenVerifier::new(&AttestationTokenVerifierConfig {
            attestation_token_type: AttestationTokenVerifierType::Jwk,
            trusted_certs_paths: vec![config.certs_file.clone()],
        })
        .await
        .context("Failed to initialize token verifier")?;

        Ok(Self {
            config: config.clone(),
            token_verifier,
        })
    }
}
