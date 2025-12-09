// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use std::path::PathBuf;
use std::sync::Arc;

mod opa;

mod error;
pub use error::*;

pub const DEFAULT_POLICY_PATH: &str = "/opt/confidential-containers/kbs/policy.rego";

/// Resource policy engine interface
///
/// TODO: Use a better authentication and authorization policy
#[async_trait]
pub(crate) trait PolicyEngineInterface: Send + Sync {
    /// Determine whether there is access to a specific path based on the input claims.
    /// Input parameters:
    /// data: data to be evaluated for regorus (rego) engine, in JSON format.
    /// input_claims: input claims to be evaluated for regorus (rego) engine, in JSON format.
    ///
    /// return value:
    /// (decide_result)
    /// decide_result: Boolean value to present whether the evaluate is passed or not.
    async fn evaluate(&self, data: &str, input_claims: &str) -> Result<bool>;

    /// Set policy (Base64 encode)
    async fn set_policy(&mut self, policy: &str) -> Result<()>;

    /// Get policy (Base64 encode)
    async fn get_policy(&self) -> Result<String>;
}

/// Policy engine configuration.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct PolicyEngineConfig {
    /// Path to a file containing a policy for evaluating whether the TCB status has access to
    /// specific resources.
    pub policy_path: PathBuf,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            policy_path: PathBuf::from(DEFAULT_POLICY_PATH),
        }
    }
}

/// Policy Engine
#[derive(Clone)]
pub(crate) struct PolicyEngine(pub Arc<Mutex<dyn PolicyEngineInterface>>);

impl PolicyEngine {
    /// Create and initialize PolicyEngine
    pub async fn new(config: &PolicyEngineConfig) -> Result<Self> {
        let policy_engine: Arc<Mutex<dyn PolicyEngineInterface>> =
            Arc::new(Mutex::new(opa::Opa::new(config.policy_path.clone())?));
        Ok(Self(policy_engine))
    }

    pub async fn evaluate(&self, data: &str, input_claims: &str) -> Result<bool> {
        self.0.lock().await.evaluate(data, input_claims).await
    }

    pub async fn set_policy(&self, request: &[u8]) -> Result<()> {
        let request: Value = serde_json::from_slice(request).map_err(|_| {
            KbsPolicyEngineError::IllegalSetPolicyRequest("Illegal SetPolicy Request Json")
        })?;
        let policy = request
            .pointer("/policy")
            .ok_or(KbsPolicyEngineError::IllegalSetPolicyRequest(
                "No `policy` field inside SetPolicy Request Json",
            ))?
            .as_str()
            .ok_or(KbsPolicyEngineError::IllegalSetPolicyRequest(
                "`policy` field is not a string in SetPolicy Request Json",
            ))?;
        self.0.lock().await.set_policy(policy).await
    }

    pub async fn get_policy(&self) -> Result<String> {
        self.0.lock().await.get_policy().await
    }
}
