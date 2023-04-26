// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::Attest;
use anyhow::*;
use as_types::AttestationResults;
use async_trait::async_trait;
use attestation_service::{config::Config as AsConfig, AttestationService};
use kbs_types::Tee;
use std::path::Path;

pub struct Native {
    inner: AttestationService,
}

#[async_trait]
impl Attest for Native {
    async fn verify(
        &mut self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults> {
        self.inner.evaluate(tee, nonce, attestation).await
    }
}

impl Native {
    pub fn new(as_config_path: &Option<String>) -> Result<Self> {
        let as_config = match as_config_path {
            Some(path) => AsConfig::try_from(Path::new(&path))
                .map_err(|e| anyhow!("Read AS config file failed: {:?}", e))?,
            None => AsConfig::default(),
        };

        Ok(Self {
            inner: AttestationService::new(as_config)?,
        })
    }
}
