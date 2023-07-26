// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(feature = "opa")]
mod opa;

const DEFAULT_POLICY_PATH: &str = "/opa/confidential-containers/kbs/policy.rego";

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
    async fn evaluate(&self, resource_path: String, input_claims: String)
        -> Result<(bool, String)>;

    /// Set policy (Base64 encode)
    async fn set_policy(&mut self, policy: String) -> Result<()>;
}

/// Policy Engine
#[derive(Clone)]
pub(crate) struct PolicyEngine(pub Arc<Mutex<dyn PolicyEngineInterface>>);

impl PolicyEngine {
    /// Create and initialize PolicyEngine
    pub async fn new(kbs_config: &Config) -> Result<Self> {
        let policy_engine: Arc<Mutex<dyn PolicyEngineInterface>> = {
            cfg_if::cfg_if! {
                if #[cfg(feature = "opa")] {
                    Arc::new(Mutex::new(opa::Opa::new(kbs_config.policy_path.clone().unwrap_or(PathBuf::from(DEFAULT_POLICY_PATH)))?))
                } else {
                    compile_error!("Please enable at least one of the following features: `opa` to continue.");
                }
            }
        };
        Ok(Self(policy_engine))
    }
}
