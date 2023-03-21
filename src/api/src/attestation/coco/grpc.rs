// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::Attest;
use crate::config::Config;
use anyhow::*;
use as_types::AttestationResults;
use async_trait::async_trait;
use kbs_types::Tee;
use log::info;
use tonic::transport::Channel;

use self::attestation::{
    attestation_service_client::AttestationServiceClient, AttestationRequest, SetPolicyRequest,
    Tee as GrpcTee,
};

mod attestation {
    #![allow(unknown_lints)]
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("attestation");
}

pub const DEFAULT_AS_ADDR: &str = "http://127.0.0.1:50004";

fn to_grpc_tee(tee: Tee) -> GrpcTee {
    match tee {
        Tee::AzSnpVtpm => GrpcTee::AzSnpVtpm,
        Tee::Cca => todo!(),
        Tee::Sample => GrpcTee::Sample,
        Tee::Sev => GrpcTee::Sev,
        Tee::Sgx => GrpcTee::Sgx,
        Tee::Snp => GrpcTee::Snp,
        Tee::Tdx => GrpcTee::Tdx,
    }
}

pub struct Grpc {
    inner: AttestationServiceClient<Channel>,
}

impl Grpc {
    pub async fn new(kbs_config: &Config) -> Result<Self> {
        let as_addr = match &kbs_config.as_addr {
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
    async fn set_policy(&mut self, input: as_types::SetPolicyInput) -> Result<()> {
        let req = tonic::Request::new(SetPolicyRequest {
            input: serde_json::to_string(&input)?,
        });

        let _ = self
            .inner
            .set_attestation_policy(req)
            .await
            .map_err(|e| anyhow!("Set Policy Failed: {:?}", e))?;

        Ok(())
    }

    async fn verify(
        &mut self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults> {
        let req = tonic::Request::new(AttestationRequest {
            tee: to_grpc_tee(tee) as i32,
            nonce: String::from(nonce),
            evidence: String::from(attestation),
        });

        let results_string = self
            .inner
            .attestation_evaluate(req)
            .await?
            .into_inner()
            .attestation_results;
        let result: AttestationResults = serde_json::from_str(&results_string)
            .map_err(|_| anyhow!("Deserialize Attest Result failed"))?;

        Ok(result)
    }
}
