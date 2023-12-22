// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::Attest;
use anyhow::*;
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{Attestation, Tee};
use log::info;
use serde::Deserialize;
use serde_json::json;
use tonic::transport::Channel;

use self::attestation::{
    attestation_request::RuntimeData, attestation_service_client::AttestationServiceClient,
    AttestationRequest, SetPolicyRequest, Tee as GrpcTee,
};

mod attestation {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("attestation");
}

pub const DEFAULT_AS_ADDR: &str = "http://127.0.0.1:50004";

pub const COCO_AS_HASH_ALGORITHM: &str = "sha384";

fn to_grpc_tee(tee: Tee) -> GrpcTee {
    match tee {
        Tee::AzSnpVtpm => GrpcTee::AzSnpVtpm,
        Tee::Cca => GrpcTee::Cca,
        Tee::Csv => GrpcTee::Csv,
        Tee::Sample => GrpcTee::Sample,
        Tee::Sev => GrpcTee::Sev,
        Tee::Sgx => GrpcTee::Sgx,
        Tee::Snp => GrpcTee::Snp,
        Tee::Tdx => GrpcTee::Tdx,
        Tee::AzTdxVtpm => GrpcTee::AzTdxVtpm,
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct GrpcConfig {
    as_addr: Option<String>,
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            as_addr: Some(DEFAULT_AS_ADDR.to_string()),
        }
    }
}

pub struct Grpc {
    inner: AttestationServiceClient<Channel>,
}

impl Grpc {
    pub async fn new(config: &GrpcConfig) -> Result<Self> {
        let as_addr = match &config.as_addr {
            Some(addr) => addr.clone(),
            None => {
                log::info!("Default remote AS address (127.0.0.1:50004) is used");
                DEFAULT_AS_ADDR.to_string()
            }
        };

        info!("connect to remote AS [{as_addr}]");
        let inner = AttestationServiceClient::connect(as_addr).await?;
        Ok(Self { inner })
    }
}

#[async_trait]
impl Attest for Grpc {
    async fn set_policy(&mut self, input: &[u8]) -> Result<()> {
        let input = String::from_utf8(input.to_vec()).context("parse SetPolicyInput")?;
        let req = tonic::Request::new(SetPolicyRequest { input });

        let _ = self
            .inner
            .set_attestation_policy(req)
            .await
            .map_err(|e| anyhow!("Set Policy Failed: {:?}", e))?;

        Ok(())
    }

    async fn verify(&mut self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        let attestation: Attestation = serde_json::from_str(attestation)?;

        // TODO: align with the guest-components/kbs-protocol side.
        let runtime_data_plaintext = json!({"tee-pubkey": attestation.tee_pubkey, "nonce": nonce});
        let runtime_data_plaintext = serde_json::to_string(&runtime_data_plaintext)
            .context("CoCo AS client: serialize runtime data failed")?;

        let req = tonic::Request::new(AttestationRequest {
            tee: to_grpc_tee(tee).into(),
            evidence: URL_SAFE_NO_PAD.encode(attestation.tee_evidence),
            runtime_data_hash_algorithm: COCO_AS_HASH_ALGORITHM.into(),
            init_data_hash_algorithm: COCO_AS_HASH_ALGORITHM.into(),
            runtime_data: Some(RuntimeData::StructuredRuntimeData(runtime_data_plaintext)),
            init_data: None,
            policy_ids: vec!["default".to_string()],
        });

        let token = self
            .inner
            .attestation_evaluate(req)
            .await?
            .into_inner()
            .attestation_token;

        Ok(token)
    }
}
