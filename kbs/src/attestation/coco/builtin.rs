// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use attestation_service::{
    config::VerifierConfig, ear_token::EarTokenConfiguration, rvps::RvpsConfig, AttestationService,
    HashAlgorithm, InitDataInput, RuntimeData, VerificationRequest,
};
use kbs_types::{Challenge, Tee};
use key_value_storage::StorageBackendConfig;
use serde::Deserialize;
use tokio::sync::RwLock;

use crate::attestation::backend::{make_nonce, Attest, IndependentEvidence};

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct Config {
    /// Configurations for RVPS.
    #[serde(default)]
    pub rvps_config: RvpsConfig,

    /// The Attestation Result Token Broker Config
    #[serde(default)]
    pub attestation_token_broker: EarTokenConfiguration,

    /// Optional configuration for verifier modules
    #[serde(default)]
    pub verifier_config: Option<VerifierConfig>,
}

impl Config {
    pub fn derive_as_config(
        &self,
        storage_backend_config: &StorageBackendConfig,
    ) -> attestation_service::config::Config {
        attestation_service::config::Config {
            rvps_config: self.rvps_config.clone(),
            attestation_token_broker: self.attestation_token_broker.clone(),
            verifier_config: self.verifier_config.clone(),
            storage_backend: storage_backend_config.clone(),
        }
    }
}

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
        self.inner
            .write()
            .await
            .register_reference_value(message)
            .await
    }

    async fn query_reference_value(
        &self,
        reference_value_id: &str,
    ) -> anyhow::Result<Option<serde_json::Value>> {
        let rvs = self
            .inner
            .read()
            .await
            .query_reference_value(reference_value_id)
            .await?;
        Ok(rvs)
    }
}

impl BuiltInCoCoAs {
    pub async fn new(
        config: Config,
        storage_backend_config: &StorageBackendConfig,
    ) -> Result<Self> {
        let config = config.derive_as_config(storage_backend_config);
        let inner = RwLock::new(AttestationService::new(config).await?);
        Ok(Self { inner })
    }
}
