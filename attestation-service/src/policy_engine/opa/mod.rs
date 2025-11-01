// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;
use std::{collections::HashMap, thread};
use tracing::{debug, instrument, warn};

use crate::rvps::RvpsClient;

use super::{EvaluationResult, PolicyDigest, PolicyEngine, PolicyError};

/// The rule to evaluate the policy.
/// Note that only the result of this rule will be returned.
pub const EVAL_RULE: &str = "data.policy.result";

#[derive(Debug, Clone)]
pub struct OPA {
    policy_dir_path: PathBuf,
}

impl OPA {
    pub fn new(work_dir: PathBuf) -> Result<Self, PolicyError> {
        let mut policy_dir_path = work_dir;

        policy_dir_path.push("opa");
        if !policy_dir_path.as_path().exists() {
            fs::create_dir_all(&policy_dir_path).map_err(PolicyError::CreatePolicyDirFailed)?;
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
    #[instrument(skip_all, name = "OPA", fields(policy_id = %policy_id))]
    async fn evaluate(
        &self,
        data: Option<&str>,
        input: &str,
        policy_id: &str,
        rvps_client: Option<RvpsClient>,
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

        if let Some(data) = data {
            let data = regorus::Value::from_json_str(data)
                .map_err(PolicyError::JsonSerializationFailed)?;

            engine
                .add_data(data)
                .map_err(PolicyError::LoadReferenceDataFailed)?;
        }

        // Add TCB claims as input
        engine
            .set_input_json(input)
            .context("set input")
            .map_err(PolicyError::SetInputDataFailed)?;

        if let Some(rvps_client) = rvps_client {
            engine
                .add_extension(
                    "query_reference_value".to_string(),
                    1,
                    Box::new(move |params: Vec<regorus::Value>| {
                        if params.len() != 1 {
                            bail!("query_reference_value extension requires exactly one parameter");
                        }
                        let id = params[0]
                            .as_string()
                            .context("query_reference_value extension parameter must be a string")?
                            .to_string();
                        debug!("query reference value from RVPS: {id}");
                        let (tx, rx) = mpsc::channel::<Result<Option<serde_json::Value>>>();

                        let fut = async |rvps_client: RvpsClient,
                                         reference_value_id: String|
                               -> Result<_> {
                            let rv = rvps_client
                                .lock()
                                .await
                                .query_reference_value(&reference_value_id)
                                .await?;
                            Ok(rv)
                        };

                        let rvps_client = rvps_client.clone();
                        let reference_value_id = params[0].as_string()?.to_string();
                        let _ = thread::spawn(move || {
                            let rt = tokio::runtime::Builder::new_current_thread()
                                .enable_all()
                                .build()
                                .expect("failed to build runtime");

                            let res = rt.block_on(fut(rvps_client, reference_value_id));

                            tx.send(res)
                        });

                        // We wait for 10 seconds at most.
                        match rx.recv_timeout(Duration::from_secs(10)) {
                            Ok(Ok(Some(v))) => {
                                let json_value = serde_json::to_value(v)?;
                                let value: regorus::Value = serde_json::from_value(json_value)?;
                                Ok(value)
                            }
                            Ok(Ok(None)) => {
                                warn!("No reference value found for the given id: {id}, use NULL as the returned value");
                                Ok(regorus::Value::Null)
                            }
                            Ok(Err(e)) => bail!("Get Reference Value from RVPS failed: {e:?}"),
                            Err(e) => bail!("Get Reference Value from RVPS timeout: {e:?}"),
                        }
                    }),
                )
                .expect("Only duplicated extension insertion can cause panic");
        }

        let claim_value =
            engine
                .eval_rule(EVAL_RULE.to_string())
                .map_err(|e| PolicyError::EvalPolicyFailed {
                    policy_id: policy_id.to_string(),
                    source: e,
                })?;

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

    async fn set_policy(
        &self,
        policy_id: String,
        policy: String,
        overwrite: bool,
    ) -> Result<(), PolicyError> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(policy)?;

        if !Self::is_valid_policy_id(&policy_id) {
            return Err(PolicyError::InvalidPolicyId);
        }

        // Check if the policy is valid
        {
            let policy_content = String::from_utf8(policy_bytes.clone())
                .map_err(|e| PolicyError::InvalidPolicy(e.into()))?;
            let mut engine = regorus::Engine::new();
            engine
                .add_policy(policy_id.clone(), policy_content)
                .map_err(PolicyError::InvalidPolicy)?;
        }

        let mut policy_file_path = PathBuf::from(
            &self
                .policy_dir_path
                .to_str()
                .ok_or_else(|| PolicyError::PolicyDirPathToStringFailed)?,
        );

        policy_file_path.push(format!("{policy_id}.rego"));

        if !overwrite && policy_file_path.exists() {
            warn!("Policy {policy_id} already exists, so the default policy will not be written.");
            return Ok(());
        }

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

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use serde_json::json;

    use super::*;

    fn dummy_reference(svn: u64, launch_digest: String) -> String {
        json!({
            "reference": {
                "svn": [svn.to_string()],
                "launch_digest": [launch_digest],
                "major_version": 1,
                "minimum_minor_version": 1
            }
        })
        .to_string()
    }

    fn dummy_input(svn: u64, launch_digest: String) -> String {
        json!({
            "sample": {
                "svn": svn.to_string(),
                "launch_digest": launch_digest,
                "platform_version": {
                    "major": 1,
                    "minor": 4
                }
            }
        })
        .to_string()
    }

    #[rstest]
    #[case(1,1,"aac43bb3".to_string(),"aac43bb3".to_string(),3,2)]
    #[case(2,1,"aac43bb3".to_string(),"aac43bb3".to_string(),3,97)]
    #[case(1,1,"aac43bb4".to_string(),"aac43bb3".to_string(),33,2)]
    #[case(2,1,"aac43bb4".to_string(),"aac43bb3".to_string(),33,97)]
    #[tokio::test]
    async fn test_evaluate(
        #[case] svn_a: u64,
        #[case] svn_b: u64,
        #[case] digest_a: String,
        #[case] digest_b: String,
        #[case] ex_exp: i64,
        #[case] hw_exp: i64,
    ) {
        let opa = OPA {
            policy_dir_path: PathBuf::from("./tests/policy/"),
        };
        let default_policy_id = "ear_sample".to_string();

        let output = opa
            .evaluate(
                Some(&dummy_reference(svn_a, digest_a)),
                &dummy_input(svn_b, digest_b),
                &default_policy_id,
                None,
            )
            .await
            .unwrap();

        println!("{:?}", output.rules_result);
        assert_eq!(
            hw_exp,
            output
                .rules_result
                .as_object()
                .unwrap()
                .get("hardware")
                .unwrap()
                .as_i64()
                .unwrap()
        );
        assert_eq!(
            ex_exp,
            output
                .rules_result
                .as_object()
                .unwrap()
                .get("executables")
                .unwrap()
                .as_i64()
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_policy_management() {
        let opa = OPA::new(PathBuf::from("tests/tmp")).unwrap();
        let policy = "package policy
default allow = true"
            .to_string();

        let get_policy_output = "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU".to_string();

        assert!(opa
            .set_policy(
                "test".to_string(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy),
                true
            )
            .await
            .is_ok());
        let policy_list = opa.list_policies().await.unwrap();
        assert_eq!(policy_list.len(), 1);
        let test_policy = opa.get_policy("test".to_string()).await.unwrap();
        assert_eq!(test_policy, get_policy_output);
        assert!(opa.list_policies().await.is_ok());
    }
}
