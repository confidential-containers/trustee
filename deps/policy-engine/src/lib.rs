// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

pub mod policy;
pub use policy::*;

pub mod error;
pub use error::*;
use key_value_storage::SetParameters;

pub use key_value_storage::KeyValueStorage;

pub trait EngineTrait {
    /// The suffix of the policy file.
    /// Concrete policy engine backend may handle the policy in different ways.
    /// For example, the policy engine may store the policy in a different format.
    /// In this case, the policy engine may need to add a suffix to the policy id to distinguish the policy.
    /// This is also for compatibility with the existing policy setting and getting
    /// APIs. Concretely, users do not need to specify the `.rego` suffix.
    fn policy_suffix() -> &'static str {
        ""
    }
}

#[derive(Clone)]
pub struct PolicyEngine<T: Send + Sync + EngineTrait> {
    pub storage: Arc<dyn KeyValueStorage>,
    pub engine: T,
}

impl<T: Send + Sync + EngineTrait> PolicyEngine<T> {
    /// Set a policy to the backend.
    /// The policy is expected to be provided as string.
    /// Concrete policy engine backend may handle the policy in different ways.
    pub async fn set_policy(&self, policy_id: &str, policy: &str, overwrite: bool) -> Result<()> {
        let params = SetParameters { overwrite };
        let policy_id = format!("{}{}", policy_id, T::policy_suffix());
        let _ = self
            .storage
            .set(&policy_id, policy.as_bytes(), params)
            .await
            .map_err(PolicyError::from)?;
        Ok(())
    }

    /// List all policies in the backend.
    pub async fn list_policies(&self) -> Result<Vec<String>> {
        let policies = self.storage.list().await?;
        let policies = policies
            .into_iter()
            .map(|policy| policy.strip_suffix(T::policy_suffix()).map(|p|p.to_string()).ok_or(PolicyError::MalformedPolicy(anyhow::anyhow!("There is at least one policy in the storage with invalid name. The policy name should contain the policy suffix {}.", T::policy_suffix()))))
            .collect::<Result<Vec<String>>>()?;
        Ok(policies)
    }

    /// Get a policy from the backend.
    /// The policy is expected to be provided as string.
    /// Concrete policy engine backend may handle the policy in different ways.
    pub async fn get_policy(&self, policy_id: &str) -> Result<String> {
        let policy_id = format!("{}{}", policy_id, T::policy_suffix());
        let policy_str = self.storage.get(&policy_id).await?;

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
