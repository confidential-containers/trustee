// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use key_value_storage::KeyValueStorageInstance;
use regorus::Extension;
use serde_json::Value;
use tracing::{info, instrument};

use crate::{EngineTrait, EvaluationResult, PolicyEngine, PolicyError, Result};

/// The rule to evaluate the policy.
/// Note that only the result of this rule will be returned.
pub const EVAL_RULE: &str = "data.policy.result";

pub struct RegorusExtension {
    pub name: String,
    pub id: u8,
    pub extension: Box<dyn Extension + Send + Sync>,
}

#[derive(Debug, Clone, Default)]
pub struct Regorus {}

impl EngineTrait for Regorus {
    fn policy_suffix() -> &'static str {
        ".rego"
    }
}

impl Regorus {
    /// The inputs to an policy engine. Inspired by OPA, we divided the inputs
    /// into three parts:
    /// - `data`: static data that will help to enforce the policy.
    /// - `input`: dynamic data that will help to enforce the policy.
    /// - `policy`: the policy to be enforced.
    #[instrument(skip_all, name = "Regorus")]
    pub async fn evaluate(
        &self,
        data: Option<&str>,
        input: &str,
        policy: &str,
        eval_rules: Vec<&str>,
        extensions: Vec<RegorusExtension>,
    ) -> Result<EvaluationResult> {
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

        if let Some(data) = data {
            let data = regorus::Value::from_json_str(data)
                .map_err(PolicyError::JsonSerializationFailed)?;

            engine
                .add_data(data)
                .map_err(PolicyError::LoadReferenceDataFailed)?;
        }

        engine
            .set_input_json(input)
            .map_err(PolicyError::SetInputDataFailed)?;

        for extension in extensions {
            engine
                .add_extension(extension.name.clone(), extension.id, extension.extension)
                .map_err(|e| PolicyError::AddRegorusExtensionFailed {
                    name: extension.name,
                    id: extension.id,
                    source: e,
                })?;
        }

        let eval_rules_result = eval_rules
            .iter()
            .map(|rule| {
                let value = match engine.eval_rule(rule.to_string()) {
                    Ok(r) => Some(r),
                    // Extensions claim is optional.
                    Err(e) if e.to_string().contains("not a valid rule path") => {
                        info!("No claim {rule} found in policy.");
                        None
                    }
                    Err(e) => return Err(PolicyError::EvalPolicyFailed(e)),
                };
                if let Some(value) = value {
                    let value = serde_json::to_value(value)
                        .map_err(|e| PolicyError::JsonSerializationFailed(e.into()))?;
                    Ok((rule.to_string(), Some(value)))
                } else {
                    Ok((rule.to_string(), None))
                }
            })
            .collect::<Result<HashMap<String, Option<Value>>>>()?;

        let res = EvaluationResult {
            eval_rules_result,
            policy_hash,
        };

        Ok(res)
    }
}

impl PolicyEngine<Regorus> {
    pub fn new(storage: KeyValueStorageInstance) -> Self {
        let engine = Regorus::default();
        Self { storage, engine }
    }

    pub async fn evaluate_rego(
        &self,
        data: Option<&str>,
        input: &str,
        policy_id: &str,
        eval_rules: Vec<&str>,
        extensions: Vec<RegorusExtension>,
    ) -> Result<EvaluationResult> {
        let policy = self.get_policy(policy_id).await?;
        self.engine
            .evaluate(data, input, &policy, eval_rules, extensions)
            .await
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
        use crate::rego::Regorus;

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
        let result = engine
            .evaluate(
                Some(&data),
                &input,
                &policy,
                vec!["data.policy.result"],
                vec![],
            )
            .await
            .unwrap();
        assert_eq!(
            result
                .eval_rules_result
                .get("data.policy.result")
                .unwrap()
                .as_ref()
                .unwrap()
                .as_bool()
                .unwrap(),
            expected
        );
    }
}
