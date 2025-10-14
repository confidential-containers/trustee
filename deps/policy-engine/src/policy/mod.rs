// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use crate::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use strum::EnumString;

pub mod rego;

#[async_trait]
pub trait Engine: Send + Sync {
    /// The inputs to an policy engine. Inspired by OPA, we divided the inputs
    /// into three parts:
    /// - `data`: static data that will help to enforce the policy.
    /// - `input`: dynamic data that will help to enforce the policy.
    /// - `policy`: the policy to be enforced.
    async fn evaluate(&self, data: &str, input: &str, policy: &str) -> Result<EvaluationResult>;
}

#[derive(Debug, EnumString, Deserialize, Clone, Default, PartialEq)]
#[strum(ascii_case_insensitive)]
pub enum PolicyType {
    #[default]
    Rego,
}

#[derive(Debug)]
pub struct EvaluationResult {
    pub rules_result: Value,
    pub policy_hash: String,
}

impl PolicyType {
    pub fn to_engine(&self) -> Arc<dyn Engine> {
        match self {
            PolicyType::Rego => Arc::new(crate::policy::rego::Regorus::default()),
        }
    }
}
