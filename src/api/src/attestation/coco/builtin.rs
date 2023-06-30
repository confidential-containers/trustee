// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::Attest;
use anyhow::*;
use async_trait::async_trait;
use attestation_service::{config::Config as AsConfig, AttestationService};
use kbs_types::Tee;

pub struct Native {
    inner: AttestationService,
}

#[async_trait]
impl Attest for Native {
    async fn set_policy(&mut self, input: as_types::SetPolicyInput) -> Result<()> {
        self.inner.set_policy(input).await
    }
    async fn verify(&mut self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        self.inner.evaluate(tee, nonce, attestation).await
    }
}

impl Native {
    pub fn new(config: &AsConfig) -> Result<Self> {
        Ok(Self {
            inner: AttestationService::new(config.clone())?,
        })
    }
}
