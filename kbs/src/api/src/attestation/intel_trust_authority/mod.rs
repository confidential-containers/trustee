// Copyright (c) 2023 by Intel.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::Attest;
use anyhow::*;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, jwk, DecodingKey, Validation};
use kbs_types::{Attestation, Tee};
use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;

#[derive(Deserialize, Debug)]
struct IntelTrustAuthorityTeeEvidence {
    #[serde(skip)]
    _cc_eventlog: Option<String>,
    quote: String,
}

#[derive(Serialize, Debug)]
struct AttestReqData {
    quote: String,
}

#[derive(Deserialize, Debug)]
struct AttestRespData {
    token: String,
}

#[derive(Deserialize, Debug)]
struct Claims {
    policy_ids_unmatched: Option<Vec<serde_json::Value>>,
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
    certs: jwk::JwkSet,
}

#[async_trait]
impl Attest for IntelTrustAuthority {
    async fn verify(&self, tee: Tee, _nonce: &str, attestation: &str) -> Result<String> {
        if tee != Tee::Tdx && tee != Tee::Sgx {
            bail!("Intel Trust Authority: TEE {tee:?} is not supported.");
        }
        // get quote
        let attestation = serde_json::from_str::<Attestation>(attestation)
            .map_err(|e| anyhow!("Deserialize Attestation failed: {:?}", e))?;
        let evidence =
            serde_json::from_str::<IntelTrustAuthorityTeeEvidence>(&attestation.tee_evidence)
                .map_err(|e| anyhow!("Deserialize supported TEE Evidence failed: {:?}", e))?;

        // construct attest request data
        let req_data = AttestReqData {
            quote: evidence.quote,
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

        if resp.status() != reqwest::StatusCode::OK {
            bail!(
                "Attestation request failed: respone status={}",
                resp.status()
            );
        }

        // get token kid
        let resp_data = resp
            .json::<AttestRespData>()
            .await
            .map_err(|e| anyhow!("Deserialize attestation respone failed: {:?}", e))?;
        let header = decode_header(&resp_data.token)
            .map_err(|e| anyhow!("Decode token header failed: {:?}", e))?;
        let kid = header.kid.ok_or(anyhow!("Token missing kid"))?;

        log::debug!("token={}", &resp_data.token);

        // find jwk
        let key = self.certs.find(&kid).ok_or(anyhow!("Find jwk failed"))?;
        let alg = key.common.algorithm.ok_or(anyhow!("Get jwk alg failed"))?;

        // verify and decode token
        let dkey = DecodingKey::from_jwk(&key)?;
        let token = decode::<Claims>(&resp_data.token, &dkey, &Validation::new(alg))
            .map_err(|e| anyhow!("Decode token failed: {:?}", e))?;

        // check unmatched policy
        let allow = self.config.allow_unmatched_policy.unwrap_or(false);
        if allow == false && token.claims.policy_ids_unmatched.is_some() {
            bail!("Evidence doesn't match policy");
        }

        Ok(resp_data.token.clone())
    }
}

impl IntelTrustAuthority {
    pub fn new(config: IntelTrustAuthorityConfig) -> Result<Self> {
        let file = File::open(&config.certs_file)
            .map_err(|e| anyhow!("Open certs file failed: {:?}", e))?;
        let reader = BufReader::new(file);

        Ok(Self {
            config: config.clone(),
            certs: serde_json::from_reader(reader)
                .map_err(|e| anyhow!("Deserialize certs failed: {:?}", e))?,
        })
    }
}
