// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use strum::EnumString;

pub mod opa;

#[async_trait]
pub trait Engine: Send + Sync {
    /// The inputs to an policy engine. Inspired by OPA, we divided the inputs
    /// into three parts:
    /// - `policy id`: indicates the policy id that will be used to perform policy
    /// enforcement
    /// - `policy`: the policy to be enforced.
    /// - `data`: static data that will help to enforce the policy.
    /// - `input`: dynamic data that will help to enforce the policy.
    /// - `rules`: the decision statement to be executed by the policy engine
    /// to determine the final output.
    ///
    /// In CoCoAS scenarios, `data` is recommended to carry reference values as
    /// it is relatively static. `input` is recommended to carry `tcb_claims`
    /// returned by `verifier` module. Concrete implementation can be different
    /// due to different needs.
    async fn evaluate(
        &self,
        data: &str,
        input: &str,
        policy_id: &str,
        policy: &str,
    ) -> Result<EvaluationResult>;
}

#[derive(Debug, EnumString, Deserialize, Clone, Default, PartialEq)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    #[default]
    Opa,
}

#[derive(Debug)]
pub struct EvaluationResult {
    pub rules_result: Value,
    pub policy_hash: String,
}

impl PolicyEngineType {
    pub fn to_engine(&self) -> Arc<dyn Engine> {
        match self {
            PolicyEngineType::Opa => Arc::new(crate::engine::opa::Opa::default()),
        }
    }
}
