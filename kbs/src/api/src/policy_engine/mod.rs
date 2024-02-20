// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

#[cfg(feature = "opa")]
mod opa;

const DEFAULT_POLICY_PATH: &str = "/opa/confidential-containers/kbs/policy.rego";

#[derive(Error, Debug)]
pub enum ResourcePolicyError {
    #[error("Failed to evaluate resource policy {0}")]
    EvaluationError(#[from] anyhow::Error),

    #[error("Failed to load data for resource policy")]
    DataLoadError,

    #[error("Invalid resource path format")]
    ResourcePathError,

    #[error("Resource Policy IO Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Decoding (base64) resource policy failed: {0}")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Failed to load input for resource policy")]
    InputError,

    #[error("Failed to load resource policy")]
    PolicyLoadError,
}

/// Resource policy engine interface
#[async_trait]
pub(crate) trait PolicyEngineInterface: Send + Sync {
    /// Determine whether there is access to a specific path resource based on the input claims.
    /// Input parameters:
    /// resource_path: Required to be a string in three segment path format:<TOP>/<MIDDLE>/<TAIL>, for example: "my'repo/License/key".
    /// input_claims: Parsed claims from Attestation Token.
    ///
    /// return value:
    /// ([decide_result, extra_output])
    /// decide_result: Boolean value to present whether the evaluate is passed or not.
    /// extra_output: original ouput from policy engine.
    async fn evaluate(
        &self,
        resource_path: String,
        input_claims: String,
    ) -> Result<bool, ResourcePolicyError>;

    /// Set policy (Base64 encode)
    async fn set_policy(&mut self, policy: String) -> Result<(), ResourcePolicyError>;
}

/// Policy engine configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct PolicyEngineConfig {
    /// Path to a file containing a policy for evaluating whether the TCB status has access to
    /// specific resources.
    pub policy_path: Option<PathBuf>,
}

impl Default for PolicyEngineConfig {
    fn default() -> Self {
        Self {
            policy_path: Some(PathBuf::from(DEFAULT_POLICY_PATH)),
        }
    }
}

/// Policy Engine
#[derive(Clone)]
pub(crate) struct PolicyEngine(pub Arc<Mutex<dyn PolicyEngineInterface>>);

impl PolicyEngine {
    /// Create and initialize PolicyEngine
    pub async fn new(config: &PolicyEngineConfig) -> Result<Self, ResourcePolicyError> {
        let policy_engine: Arc<Mutex<dyn PolicyEngineInterface>> = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "opa")] {
                    Arc::new(Mutex::new(opa::Opa::new(config.policy_path.clone().unwrap_or(PathBuf::from(DEFAULT_POLICY_PATH)))?))
                } else {
                    compile_error!("Please enable at least one of the following features: `opa` to continue.");
                }
            }
        };
        Ok(Self(policy_engine))
    }
}
