// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

pub mod rego;

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
#[serde(default)]
pub struct EvaluationResult {
    pub eval_rules_result: HashMap<String, Option<Value>>,
    pub policy_hash: String,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq)]
pub enum PolicyLanguage {
    #[default]
    Rego,
}
