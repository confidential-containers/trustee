// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

pub mod policy;
pub use policy::*;

pub mod error;
pub use error::*;
use key_value_storage::SetParameters;
use serde::Deserialize;

pub use key_value_storage::{KeyValueStorage, KeyValueStorageConfig};

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct PolicyEngineConfig {
    /// The storage to store the policies.
    pub storage: KeyValueStorageConfig,
}

#[derive(Clone)]
pub struct PolicyEngine<T: Send + Sync> {
    pub storage: Arc<dyn KeyValueStorage>,
    pub engine: T,
}

impl<T: Send + Sync> PolicyEngine<T> {
    /// Set a policy to the backend.
    /// The policy is expected to be provided as string.
    /// Concrete policy engine backend may handle the policy in different ways.
    pub async fn set_policy(&self, policy_id: &str, policy: &str, overwrite: bool) -> Result<()> {
        let params = SetParameters { overwrite };
        self.storage
            .set(policy_id, policy.as_bytes(), params)
            .await
            .map_err(From::from)
    }

    /// List all policies in the backend.
    pub async fn list_policies(&self) -> Result<Vec<String>> {
        self.storage.list().await.map_err(From::from)
    }

    /// Get a policy from the backend.
    /// The policy is expected to be provided as string.
    /// Concrete policy engine backend may handle the policy in different ways.
    pub async fn get_policy(&self, policy_id: &str) -> Result<String> {
        let policy_str = self.storage.get(policy_id).await?;

        match policy_str {
            Some(policy_str) => {
                String::from_utf8(policy_str).map_err(|e| PolicyError::PolicyIsNotUtf8String {
                    id: policy_id.to_string(),
                    source: e,
                })
            }
            None => Err(PolicyError::PolicyNotFound {
                id: policy_id.to_string(),
            }),
        }
    }
}
