// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use attestation_service::{
    config::Config as AsConfig, AttestationService, HashAlgorithm, InitDataInput, RuntimeData,
    VerificationRequest,
};
use kbs_types::{Challenge, Tee};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::attestation::backend::{make_nonce, Attest, IndependentEvidence};

pub struct BuiltInCoCoAs {
    inner: RwLock<AttestationService>,
}

#[async_trait]
impl Attest for BuiltInCoCoAs {
    async fn set_policy(&self, policy_id: &str, policy: &str) -> Result<()> {
        self.inner
            .write()
            .await
            .set_policy(policy_id.to_string(), policy.to_string())
            .await
    }

    async fn verify(&self, evidence_to_verify: Vec<IndependentEvidence>) -> Result<String> {
        let mut verification_requests = vec![];

        for evidence in evidence_to_verify {
            let mut request = VerificationRequest {
                evidence: evidence.tee_evidence,
                tee: evidence.tee,
                runtime_data: Some(RuntimeData::Structured(evidence.runtime_data)),
                runtime_data_hash_algorithm: HashAlgorithm::Sha384,
                init_data: None,
            };
            if let Some(init_data) = evidence.init_data {
                if init_data.format != "toml" {
                    bail!("Unsupported initdata format: {}", init_data.format);
                }
                request.init_data = Some(InitDataInput::Toml(init_data.body));
            }

            verification_requests.push(request);
        }

        let policy_ids = vec!["default".to_string()];
        self.inner
            .read()
            .await
            .evaluate(verification_requests, policy_ids)
            .await
    }

    async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: serde_json::Value,
    ) -> Result<Challenge> {
        let nonce = match tee {
            Tee::Se => {
                self.inner
                    .read()
                    .await
                    .generate_supplemental_challenge(tee, tee_parameters.to_string())
                    .await?
            }
            _ => make_nonce().await?,
        };

        let challenge = Challenge {
            nonce,
            extra_params: serde_json::Value::String(String::new()),
        };

        Ok(challenge)
    }

    async fn register_reference_value(&self, message: &str) -> anyhow::Result<()> {
        self.inner.write().await.register_reference_value(message)
    }

    async fn query_reference_values(&self) -> anyhow::Result<HashMap<String, serde_json::Value>> {
        self.inner.read().await.query_reference_values()
    }
}

impl BuiltInCoCoAs {
    pub async fn new(config: AsConfig) -> Result<Self> {
        let inner = RwLock::new(AttestationService::new(config).await?);
        Ok(Self { inner })
    }
}
