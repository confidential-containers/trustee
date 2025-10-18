// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use serde_json::Value;
use tracing::instrument;

use crate::{Engine, EvaluationResult, PolicyError};

/// The rule to evaluate the policy.
/// Note that only the result of this rule will be returned.
pub const EVAL_RULE: &str = "data.policy.result";

#[derive(Debug, Clone, Default)]
pub struct Regorus {}

#[async_trait]
impl Engine for Regorus {
    #[instrument(skip_all, name = "Regorus")]
    async fn evaluate(
        &self,
        data: &str,
        input: &str,
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
        // Note that the first parameter is named "path", which is used to identify the policy
        // in a same regorus::Engine instance. Now we only have one policy support thus we do not
        // need to specify different paths for different policies. Thus we use an empty string here.
        engine
            .add_policy("".to_string(), policy.to_string())
            .map_err(PolicyError::LoadPolicyFailed)?;

        let data =
            regorus::Value::from_json_str(data).map_err(PolicyError::JsonSerializationFailed)?;

        engine
            .add_data(data)
            .map_err(PolicyError::LoadReferenceDataFailed)?;

        engine
            .set_input_json(input)
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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use std::fs;

    #[tokio::test]
    #[rstest]
    #[case("my_repo/Alice/key", 1, "./test_data/policy_1.rego", false)]
    #[case("my_repo/Alice/key", 1, "./test_data/policy_4.rego", false)]
    #[case("my_repo/Alice/key", 1, "./test_data/policy_3.rego", false)]
    #[case("myrepo/secret/secret1", 2, "./test_data/policy_5.rego", true)]
    #[case("myrepo/secret/secret1", 1, "./test_data/policy_5.rego", false)]
    #[case("myrepo/secret/secret2", 3, "./test_data/policy_5.rego", true)]
    #[case("myrepo/secret/secret2", 2, "./test_data/policy_5.rego", false)]
    #[case("myrepo/secret/secret3", 3, "./test_data/policy_5.rego", false)]
    #[case("a/b/secret2", 3, "./test_data/policy_5.rego", false)]
    #[case("abc", 3, "./test_data/policy_5.rego", false)]
    async fn test_kbs_policy_evaluate(
        #[case] resource_path: &str,
        #[case] input_svn: u64,
        #[case] policy_path: &str,
        #[case] expected: bool,
    ) {
        use crate::{rego::Regorus, Engine};

        let input = format!(
            r#"
{{
    "submods": {{
        "cpu0": {{
            "ear.trustworthiness-vector": {{
                "executables": 2,
                "hardware": 3
            }},
            "ear.veraison.annotated-evidence": {{
                "sample" : {{   
                    "productId": "n",
                    "svn": {input_svn}
                }}
            }}
        }}
    }}
}}
        "#
        );

        let data = format!(
            r#"
        {{
            "resource-path": "{resource_path}"
        }}
        "#
        );
        let policy = fs::read_to_string(policy_path).unwrap();
        let engine = Regorus::default();
        let result = engine.evaluate(&data, &input, &policy).await.unwrap();
        assert_eq!(result.rules_result.as_bool().unwrap(), expected);
    }
}
