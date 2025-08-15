// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use attestation::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueQueryResponse, ReferenceValueRegisterRequest,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{Challenge, Tee};
use log::info;
use mobc::{Manager, Pool};
use serde::Deserialize;
use std::collections::HashMap;
use tonic::transport::Channel;

use crate::attestation::backend::{make_nonce, Attest, IndependentEvidence};

use self::attestation::{
    attestation_service_client::AttestationServiceClient,
    individual_attestation_request::{InitData, RuntimeData},
    AttestationRequest, ChallengeRequest, IndividualAttestationRequest, SetPolicyRequest,
};

mod attestation {
    tonic::include_proto!("attestation");
    tonic::include_proto!("reference");
}

pub const DEFAULT_AS_ADDR: &str = "http://127.0.0.1:50004";
pub const DEFAULT_POOL_SIZE: u64 = 100;

pub const COCO_AS_HASH_ALGORITHM: &str = "sha384";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct GrpcConfig {
    #[serde(default = "default_as_addr")]
    pub as_addr: String,
    #[serde(default = "default_pool_size")]
    pub pool_size: u64,
}

fn default_as_addr() -> String {
    DEFAULT_AS_ADDR.to_string()
}

fn default_pool_size() -> u64 {
    DEFAULT_POOL_SIZE
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            as_addr: DEFAULT_AS_ADDR.to_string(),
            pool_size: DEFAULT_POOL_SIZE,
        }
    }
}

pub struct GrpcClientPool {
    pool: Pool<GrpcManager>,
}

impl GrpcClientPool {
    pub async fn new(config: GrpcConfig) -> Result<Self> {
        info!(
            "connect to remote AS [{}] with pool size {}",
            config.as_addr, config.pool_size
        );
        let manager = GrpcManager {
            as_addr: config.as_addr,
        };
        let pool = Pool::builder().max_open(config.pool_size).build(manager);

        Ok(Self { pool })
    }
}

#[async_trait]
impl Attest for GrpcClientPool {
    async fn set_policy(&self, policy_id: &str, policy: &str) -> Result<()> {
        let req = tonic::Request::new(SetPolicyRequest {
            policy_id: policy_id.to_string(),
            policy: policy.to_string(),
        });

        let mut client = self.pool.get().await?;
        client
            .as_rpc
            .set_attestation_policy(req)
            .await
            .map_err(|e| anyhow!("Set Policy Failed: {:?}", e))?;

        Ok(())
    }

    async fn verify(&self, evidence_to_verify: Vec<IndependentEvidence>) -> Result<String> {
        let mut verification_requests: Vec<IndividualAttestationRequest> = vec![];

        for evidence in evidence_to_verify {
            let tee = serde_json::to_string(&evidence.tee)
                .context("CoCo AS client: serialize tee type failed.")?
                .trim_end_matches('"')
                .trim_start_matches('"')
                .to_string();

            let mut request = IndividualAttestationRequest {
                tee,
                evidence: URL_SAFE_NO_PAD.encode(evidence.tee_evidence.to_string()),
                runtime_data_hash_algorithm: COCO_AS_HASH_ALGORITHM.into(),
                runtime_data: Some(RuntimeData::StructuredRuntimeData(
                    evidence.runtime_data.to_string(),
                )),
                init_data: None,
            };

            if let Some(init_data) = evidence.init_data {
                if init_data.format != "toml" {
                    bail!("Unsupported initdata format: {}", init_data.format);
                }
                request.init_data = Some(InitData::InitDataToml(init_data.body));
            }
            verification_requests.push(request);
        }

        let attestation_request = tonic::Request::new(AttestationRequest {
            verification_requests,
            policy_ids: vec!["default".to_string()],
        });

        let mut client = self.pool.get().await?;

        let token = client
            .as_rpc
            .attestation_evaluate(attestation_request)
            .await?
            .into_inner()
            .attestation_token;

        Ok(token)
    }

    async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: serde_json::Value,
    ) -> Result<Challenge> {
        let nonce = match tee {
            Tee::Se => {
                let mut inner = HashMap::new();
                inner.insert(String::from("tee"), String::from("se"));
                inner.insert(String::from("tee_params"), tee_parameters.to_string());
                let req = tonic::Request::new(ChallengeRequest { inner });

                let mut client = self.pool.get().await?;
                client
                    .as_rpc
                    .get_attestation_challenge(req)
                    .await?
                    .into_inner()
                    .attestation_challenge
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
        let req = tonic::Request::new(ReferenceValueRegisterRequest {
            message: message.to_string(),
        });

        let mut client = self.pool.get().await?;

        client
            .rvps_rpc
            .register_reference_value(req)
            .await
            .map_err(|e| anyhow!("Failed to set reference values: {:?}", e))?;

        Ok(())
    }

    async fn query_reference_value(
        &self,
        reference_value_id: &str,
    ) -> anyhow::Result<serde_json::Value> {
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            reference_value_id: reference_value_id.to_string(),
        });

        let mut client = self.pool.get().await?;

        let ReferenceValueQueryResponse {
            reference_value_results,
        } = client
            .rvps_rpc
            .query_reference_value(req)
            .await
            .map_err(|e| anyhow!("Failed to get reference values: {:?}", e))?
            .into_inner();

        Ok(serde_json::from_str(&reference_value_results)?)
    }
}

pub struct GrpcManager {
    as_addr: String,
}

pub struct AsConnection {
    as_rpc: AttestationServiceClient<Channel>,
    rvps_rpc: ReferenceValueProviderServiceClient<Channel>,
}

#[async_trait]
impl Manager for GrpcManager {
    type Connection = AsConnection;
    type Error = Error;

    async fn connect(&self) -> Result<Self::Connection, Self::Error> {
        let connection = Channel::from_shared(self.as_addr.clone())?
            .connect()
            .await?;
        let as_rpc = AttestationServiceClient::new(connection.clone());
        let rvps_rpc = ReferenceValueProviderServiceClient::new(connection);
        Ok(AsConnection { as_rpc, rvps_rpc })
    }

    async fn check(&self, conn: Self::Connection) -> Result<Self::Connection, Self::Error> {
        Ok(conn)
    }
}
