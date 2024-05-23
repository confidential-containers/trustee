// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::{PolicyDigest, PolicyEngine};

#[derive(Debug, Clone)]
pub struct OPA {
    policy_dir_path: PathBuf,
}

impl OPA {
    pub fn new(work_dir: PathBuf) -> Result<Self> {
        let mut policy_dir_path = work_dir;

        policy_dir_path.push("opa");
        if !policy_dir_path.as_path().exists() {
            fs::create_dir_all(&policy_dir_path)
                .map_err(|e| anyhow!("Create policy dir failed: {:?}", e))?;
        }

        let mut default_policy_path = PathBuf::from(
            &policy_dir_path
                .to_str()
                .ok_or_else(|| anyhow!("Policy DirPath to string failed"))?,
        );
        default_policy_path.push("default.rego");
        if !default_policy_path.as_path().exists() {
            let policy = std::include_str!("default_policy.rego").to_string();
            fs::write(&default_policy_path, policy)?;
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
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_ids: Vec<String>,
    ) -> Result<HashMap<String, PolicyDigest>> {
        let mut res = HashMap::new();

        let policy_dir_path = self
            .policy_dir_path
            .to_str()
            .ok_or_else(|| anyhow!("Miss Policy DirPath"))?;

        for policy_id in &policy_ids {
            let input = input.clone();
            let policy_file_path = format!("{policy_dir_path}/{policy_id}.rego");

            let policy = tokio::fs::read_to_string(policy_file_path.clone())
                .await
                .context("Read OPA policy file failed")?;

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
                .add_policy(policy_id.clone(), policy)
                .context("load policy")?;

            let reference_data_map = serde_json::to_string(&reference_data_map)?;
            let reference_data_map =
                regorus::Value::from_json_str(&format!("{{\"reference\":{reference_data_map}}}"))?;
            engine
                .add_data(reference_data_map)
                .context("load reference data")?;

            // Add TCB claims as input
            engine.set_input_json(&input).context("set input")?;

            let allow = engine.eval_bool_query("data.policy.allow".to_string(), false)?;
            if !allow {
                bail!("TEE evidence does not pass policy {policy_id}");
            }

            res.insert(policy_id.clone(), policy_hash);
        }

        Ok(res)
    }

    async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(policy)
            .context("Base64 decode OPA policy string")?;

        if !Self::is_valid_policy_id(&policy_id) {
            bail!("illegal policy id. Only support alphabet, numeric, `-` or `_` ");
        }

        let mut policy_file_path = PathBuf::from(
            &self
                .policy_dir_path
                .to_str()
                .ok_or_else(|| anyhow!("Policy DirPath to string failed"))?,
        );

        policy_file_path.push(format!("{}.rego", policy_id));

        tokio::fs::write(&policy_file_path, policy_bytes)
            .await
            .map_err(|e| anyhow!("Write OPA policy to file failed: {:?}", e))
    }

    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>> {
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
                .context("Read OPA policy file failed")?;

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

    async fn get_policy(&self, policy_id: String) -> Result<String> {
        let policy_file_path = self.policy_dir_path.join(format!("{policy_id}.rego"));
        let policy = tokio::fs::read(policy_file_path)
            .await
            .context("Read OPA policy file failed")?;
        let base64_policy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(base64_policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn dummy_reference(ver: u64) -> String {
        json!({
            "productId": [ver.to_string()],
            "svn": [ver.to_string()]
        })
        .to_string()
    }

    fn dummy_input(product_id: u64, svn: u64) -> String {
        json!({
            "productId": product_id.to_string(),
            "svn": svn.to_string()
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_evaluate() {
        let opa = OPA {
            policy_dir_path: PathBuf::from("./src/policy_engine/opa"),
        };
        let default_policy_id = "default_policy".to_string();

        let reference_data: HashMap<String, Vec<String>> =
            serde_json::from_str(&dummy_reference(5)).unwrap();

        let res = opa
            .evaluate(
                reference_data.clone(),
                dummy_input(5, 5),
                vec![default_policy_id.clone()],
            )
            .await;
        let res = res.expect("OPA execution should succeed");
        // this expected value is calculated by `sha384sum`
        let expected_digest = "c0e7929671fb6780387f54760d84d65d2ce96093dfb33efda21f5eb05afcda77bba444c02cd177b23a5d350716726157";
        assert_eq!(expected_digest, res["default_policy"]);

        let res = opa
            .evaluate(reference_data, dummy_input(0, 0), vec![default_policy_id])
            .await;

        res.expect_err("OPA execution should fail");
    }

    #[tokio::test]
    async fn test_policy_management() {
        let mut opa = OPA::new(PathBuf::from("../tests/tmp")).unwrap();
        let policy = "package policy
default allow = true"
            .to_string();

        let get_policy_output = "cGFja2FnZSBwb2xpY3kKZGVmYXVsdCBhbGxvdyA9IHRydWU".to_string();

        assert!(opa
            .set_policy(
                "test".to_string(),
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy)
            )
            .await
            .is_ok());
        let policy_list = opa.list_policies().await.unwrap();
        assert_eq!(policy_list.len(), 2);
        let test_policy = opa.get_policy("test".to_string()).await.unwrap();
        assert_eq!(test_policy, get_policy_output);
        assert!(opa.list_policies().await.is_ok());
    }
}
