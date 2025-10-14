// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

pub mod engine;
pub use engine::*;

pub mod error;
pub use error::*;
use serde::Deserialize;

pub use key_value_storage::{KeyValueStorage, KeyValueStorageConfig};

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub struct PolicyEngineConfig {
    pub backend: KeyValueStorageConfig,
    pub engine: PolicyEngineType,
}

#[derive(Clone)]
pub struct PolicyEngine {
    pub backend: Arc<dyn KeyValueStorage>,
    pub engine: Arc<dyn Engine>,
}

impl PolicyEngine {
    pub async fn new(config: PolicyEngineConfig) -> Result<Self> {
        let backend = config.backend.to_key_value_storage().await?;
        let engine = config.engine.to_engine();
        Ok(Self { backend, engine })
    }

    pub async fn evaluate(
        &self,
        data: &str,
        input: &str,
        policy_id: &str,
    ) -> Result<EvaluationResult> {
        let policy = self.get_policy(policy_id).await?;
        self.engine.evaluate(data, input, policy_id, &policy).await
    }

    pub async fn set_policy(&self, policy_id: &str, policy: &str, overwrite: bool) -> Result<()> {
        self.backend
            .set_key(policy_id.to_string(), policy.to_string(), overwrite)
            .await
            .map_err(From::from)
    }

    pub async fn list_policies(&self) -> Result<Vec<String>> {
        self.backend.list_keys().await.map_err(From::from)
    }

    pub async fn get_policy(&self, policy_id: &str) -> Result<String> {
        self.backend
            .get_key(policy_id.to_string())
            .await
            .map_err(From::from)
    }
}
