// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::Attest;
use anyhow::*;
use async_trait::async_trait;
use attestation_service::{
    config::Config as AsConfig, policy_engine::SetPolicyInput, AttestationService,
};
use kbs_types::Tee;

pub struct Native {
    inner: AttestationService,
}

#[async_trait]
impl Attest for Native {
    async fn set_policy(&mut self, input: &[u8]) -> Result<()> {
        let request: SetPolicyInput =
            serde_json::from_slice(input).context("parse SetPolicyInput")?;
        self.inner.set_policy(request).await
    }

    async fn verify(&mut self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        self.inner.evaluate(tee, nonce, attestation).await
    }
}

impl Native {
    pub async fn new(config: &AsConfig) -> Result<Self> {
        Ok(Self {
            inner: AttestationService::new(config.clone()).await?,
        })
    }
}
