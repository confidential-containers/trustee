// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use log::debug;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::{EvaluationResult, PolicyDigest, PolicyEngine, PolicyError};

#[derive(Debug, Clone)]
pub struct OPA {
    policy_dir_path: PathBuf,
}

impl OPA {
    pub fn new(work_dir: PathBuf, default_policy: &str) -> Result<Self, PolicyError> {
        let mut policy_dir_path = work_dir;

        policy_dir_path.push("opa");
        if !policy_dir_path.as_path().exists() {
            fs::create_dir_all(&policy_dir_path).map_err(PolicyError::CreatePolicyDirFailed)?;
        }

        let mut default_policy_path = PathBuf::from(
            &policy_dir_path
                .to_str()
                .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?,
        );
        default_policy_path.push("default.rego");
        if !default_policy_path.as_path().exists() {
            fs::write(&default_policy_path, default_policy)
                .map_err(PolicyError::WriteDefaultPolicyFailed)?;
        }

        Ok(Self { policy_dir_path })
    }

    fn is_valid_policy_id(policy_id: &str) -> bool {
        policy_id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    }
}

#[async_trait]
impl PolicyEngine for OPA {
    async fn evaluate(
        &self,
        data: &str,
        input: &str,
        policy_id: &str,
        evaluation_rules: &[&str],
    ) -> Result<EvaluationResult, PolicyError> {
        let policy_dir_path = self
            .policy_dir_path
            .to_str()
            .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?;

        let policy_file_path = format!("{policy_dir_path}/{policy_id}.rego");

        let policy = tokio::fs::read_to_string(policy_file_path.clone())
            .await
            .map_err(PolicyError::ReadPolicyFileFailed)?;

        let mut engine = regorus::Engine::new();

        let policy_hash = {
            use sha2::Digest;
            let mut hasher = sha2::Sha384::new();
            hasher.update(&policy);
            let hex = hasher.finalize().to_vec();
            hex::encode(hex)
        };

        // Add policy as data
        engine
            .add_policy(policy_id.to_string(), policy)
            .map_err(PolicyError::LoadPolicyFailed)?;

        let data =
            regorus::Value::from_json_str(data).map_err(PolicyError::JsonSerializationFailed)?;

        engine
            .add_data(data)
            .map_err(PolicyError::LoadReferenceDataFailed)?;

        // Add TCB claims as input
        engine
            .set_input_json(input)
            .context("set input")
            .map_err(PolicyError::SetInputDataFailed)?;

        let mut rules_result = HashMap::new();
        for rule in evaluation_rules {
            let whole_rule = format!("data.policy.{rule}");
            let Ok(claim_value) = engine.eval_rule(whole_rule) else {
                debug!("Policy `{policy_id}` does not check {rule}");
                continue;
            };

            rules_result.insert(rule.to_string(), claim_value);
        }

        let res = EvaluationResult {
            rules_result,
            policy_hash,
        };

        Ok(res)
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<(), PolicyError> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(policy)?;

        if !Self::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }

        let mut policy_file_path = PathBuf::from(
            &self
                .policy_dir_path
                .to_str()
                .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?,
        );

        policy_file_path.push(format!("{}.rego", policy_id));

        tokio::fs::write(&policy_file_path, policy_bytes)
            .await
            .map_err(PolicyError::WritePolicyFileFailed)
    }

    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError> {
        let mut policy_ids = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.policy_dir_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(std::ffi::OsStr::to_str) == Some("rego") {
                if let Some(filename) = path.file_stem() {
                    if let Some(filename_str) = filename.to_str() {
                        policy_ids.push(filename_str.to_owned());
                    }
                }
            }
        }

        let mut policy_list = HashMap::new();

        for id in policy_ids.iter() {
            let policy_file_path = self.policy_dir_path.join(format!("{id}.rego"));
            let policy = tokio::fs::read(policy_file_path)
                .await
                .map_err(PolicyError::ReadPolicyFileFailed)?;

            let mut hasher = Sha384::new();
            hasher.update(policy);
            let digest = hasher.finalize().to_vec();
            policy_list.insert(
                id.to_string(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
            );
        }

        Ok(policy_list)
    }

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError> {
        let policy_file_path = self.policy_dir_path.join(format!("{policy_id}.rego"));
        let policy = tokio::fs::read(policy_file_path)
            .await
            .map_err(PolicyError::ReadPolicyFileFailed)?;
        let base64_policy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(base64_policy)
    }
}

// #[cfg(test)]
// mod tests {
//     use ear::RawValue;
//     use kbs_types::Tee;
//     use rstest::rstest;
//     use serde_json::{json, Value};
//     use std::collections::BTreeMap;
//     use crate::transform_claims;
//     use super::*;
//     fn dummy_reference(product_id: u64, svn: u64, launch_digest: String) -> String {
//         json!({
//             "productId": [product_id.to_string()],
//             "svn": [svn.to_string()],
//             "launch_digest": [launch_digest]
//         })
//         .to_string()
//     }
//     fn dummy_input(product_id: u64, svn: u64, launch_digest: String) -> BTreeMap<String, RawValue> {
//         let json_claims = json!({
//             "productId": product_id.to_string(),
//             "svn": svn.to_string(),
//             "launch_digest": launch_digest
//         });

//         let ear_claims = transform_claims(
//             json_claims,
//             Value::String("".to_string()),
//             Value::String("".to_string()),
//             Tee::Sample,
//         )
//         .unwrap();
//         ear_claims
//     }
//     #[rstest]
//     #[case(5,5,1,1,"aac43bb3".to_string(),"aac43bb3".to_string(),3,2)]
//     #[case(5,4,1,1,"aac43bb3".to_string(),"aac43bb3".to_string(),3,97)]
//     #[case(5,5,1,1,"aac43bb4".to_string(),"aac43bb3".to_string(),33,2)]
//     #[case(5,5,2,1,"aac43bb4".to_string(),"aac43bb3".to_string(),33,97)]
//     #[tokio::test]
//     async fn test_evaluate(
//         #[case] pid_a: u64,
//         #[case] pid_b: u64,
//         #[case] svn_a: u64,
//         #[case] svn_b: u64,
//         #[case] digest_a: String,
//         #[case] digest_b: String,
//         #[case] ex_exp: i8,
//         #[case] hw_exp: i8,
//     ) {
//         let opa = OPA {
//             policy_dir_path: PathBuf::from("./src/policy_engine/opa"),
//         };
//         let default_policy_id = "default_policy".to_string();

//         let reference_data: HashMap<String, Vec<String>> =
//             serde_json::from_str(&dummy_reference(pid_a, svn_a, digest_a)).unwrap();

//         let appraisal = opa
//             .evaluate(
//                 reference_data.clone(),
//                 dummy_input(pid_b, svn_b, digest_b),
//                 default_policy_id.clone(),
//             )
//             .await
//             .unwrap();

//         assert_eq!(
//             hw_exp,
//             appraisal.trust_vector.by_name("hardware").unwrap().get()
//         );
//         assert_eq!(
//             ex_exp,
//             appraisal.trust_vector.by_name("executables").unwrap().get()
//         );
//     }

//     #[tokio::test]
//     async fn test_policy_management() {
//         let mut opa = OPA::new(PathBuf::from("tests/tmp")).unwrap();
//         let policy = "package policy
// default allow = true"
//             .to_string();

//         let get_policy_output = "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU".to_string();

//         assert!(opa
//             .set_policy(
//                 "test".to_string(),
//                 base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy)
//             )
//             .await
//             .is_ok());
//         let policy_list = opa.list_policies().await.unwrap();
//         assert_eq!(policy_list.len(), 2);
//         let test_policy = opa.get_policy("test".to_string()).await.unwrap();
//         assert_eq!(test_policy, get_policy_output);
//         assert!(opa.list_policies().await.is_ok());
//     }
// }
