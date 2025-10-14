// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Context;
use async_trait::async_trait;
use serde_json::Value;
use tracing::instrument;

use crate::{Engine, EvaluationResult, PolicyError};

/// The rule to evaluate the policy.
/// Note that only the result of this rule will be returned.
pub const EVAL_RULE: &str = "data.policy.result";

#[derive(Debug, Clone, Default)]
pub struct Opa {}

#[async_trait]
impl Engine for Opa {
    #[instrument(skip_all, name = "Opa")]
    async fn evaluate(
        &self,
        data: &str,
        input: &str,
        policy_id: &str,
        policy: &str,
    ) -> Result<EvaluationResult, PolicyError> {
        let mut engine = regorus::Engine::new();

        let policy_hash = {
            use sha2::Digest;
            let mut hasher = sha2::Sha384::new();
            hasher.update(policy);
            let hex = hasher.finalize().to_vec();
            hex::encode(hex)
        };

        // Add policy as data
        engine
            .add_policy(policy_id.to_string(), policy.to_string())
            .map_err(PolicyError::LoadPolicyFailed)?;

        let data =
            regorus::Value::from_json_str(data).map_err(PolicyError::JsonSerializationFailed)?;

        engine
            .add_data(data)
            .map_err(PolicyError::LoadReferenceDataFailed)?;

        engine
            .set_input_json(input)
            .context("set input")
            .map_err(PolicyError::SetInputDataFailed)?;

        let claim_value = engine
            .eval_rule(EVAL_RULE.to_string())
            .map_err(PolicyError::EvalPolicyFailed)?;

        let claim_value = claim_value
            .to_json_str()
            .map_err(PolicyError::JsonSerializationFailed)?;
        let rules_result = serde_json::from_str::<Value>(&claim_value)?;

        let res = EvaluationResult {
            rules_result,
            policy_hash,
        };

        Ok(res)
    }
}
