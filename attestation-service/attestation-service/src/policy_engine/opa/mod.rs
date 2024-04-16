use crate::policy_engine::{PolicyDigestEntry, PolicyEngine, PolicyListEntry, PolicyType};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use log::debug;
use serde_json::Value;
use sha2::{Digest, Sha384};
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str::FromStr;

use super::{EvaluationResult, PolicyDigest, SetPolicyInput};

// Link import cgo function
#[link(name = "cgo")]
extern "C" {
    pub fn evaluateGo(policy: GoString, data: GoString, input: GoString) -> *mut c_char;
}

/// String structure passed into cgo
#[derive(Debug)]
#[repr(C)]
pub struct GoString {
    pub p: *const c_char,
    pub n: isize,
}

#[derive(Debug)]
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
}

#[async_trait]
impl PolicyEngine for OPA {
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_ids: Vec<String>,
    ) -> Result<HashMap<String, (PolicyDigest, EvaluationResult)>> {
        let mut res = HashMap::new();

        let policy_dir_path = self
            .policy_dir_path
            .to_str()
            .ok_or_else(|| anyhow!("Miss Policy DirPath"))?;

        for policy_id in policy_ids {
            let policy_file_path = format!("{policy_dir_path}/{policy_id}.rego");

            let policy = tokio::fs::read_to_string(policy_file_path)
                .await
                .map_err(|e| anyhow!("Read OPA policy file failed: {:?}", e))?;

            let policy_hash = {
                use sha2::Digest;
                let mut hasher = sha2::Sha384::new();
                hasher.update(&policy);
                let hex = hasher.finalize().to_vec();
                hex::encode(hex)
            };

            let policy_go = GoString {
                p: policy.as_ptr() as *const c_char,
                n: policy.len() as isize,
            };

            let reference = serde_json::json!({ "reference": reference_data_map }).to_string();

            let reference_go = GoString {
                p: reference.as_ptr() as *const c_char,
                n: reference.len() as isize,
            };

            let input_go = GoString {
                p: input.as_ptr() as *const c_char,
                n: input.len() as isize,
            };

            // Call the function exported by cgo and process the returned decision
            let decision_buf: *mut c_char =
                unsafe { evaluateGo(policy_go, reference_go, input_go) };
            let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
            let policy_res = decision_str.to_str()?.to_string();
            debug!("OPA Evaluated: {}", policy_res);
            if policy_res.starts_with("Error::") {
                bail!("OPA verification failed: {policy_res}");
            }

            // If a clear approval opinion is given in the evaluation report,
            // the rejection information will be reflected in the evaluation failure return value.
            let res_kv: Value = serde_json::from_str(&policy_res)?;

            // only if there is a field named `allow` in the evaluation report and
            // it is false, the evaluation fails. Otherwise the evaluation will be
            // treated as succees.
            let allow = res_kv
                .get("allow")
                .map(|a| a.as_bool())
                .map(|a| a.unwrap_or(true))
                .unwrap_or(true);

            if !allow {
                bail!("TEE evidence does not pass policy {policy_id}, reason: {policy_res}");
            } else {
                let evaluation_result =
                    serde_json::from_str(&policy_res).context("serialize OPA result")?;
                res.insert(policy_id.to_owned(), (policy_hash, evaluation_result));
            }
        }

        Ok(res)
    }

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()> {
        let policy_type = PolicyType::from_str(&input.r#type)
            .map_err(|_| anyhow!("{} is not support by AS", &input.r#type))?;
        if policy_type != PolicyType::Rego {
            bail!("OPA Policy Engine only support .rego policy");
        }

        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(input.policy)
            .map_err(|e| anyhow!("Base64 decode OPA policy string failed: {:?}", e))?;
        let mut policy_file_path = PathBuf::from(
            &self
                .policy_dir_path
                .to_str()
                .ok_or_else(|| anyhow!("Policy DirPath to string failed"))?,
        );
        policy_file_path.push(format!("{}.rego", input.policy_id));

        tokio::fs::write(&policy_file_path, policy_bytes)
            .await
            .map_err(|e| anyhow!("Write OPA policy to file failed: {:?}", e))
    }

    async fn list_policies(&self) -> Result<Vec<PolicyListEntry>> {
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

        let mut policy_list = Vec::new();

        for id in policy_ids.iter() {
            let policy_file_path = self.policy_dir_path.join(format!("{id}.rego"));
            let policy = tokio::fs::read(policy_file_path)
                .await
                .context("Read OPA policy file failed")?;

            let mut hasher = Sha384::new();
            hasher.update(policy);
            let digest = hasher.finalize().to_vec();
            policy_list.push(PolicyListEntry {
                id: id.to_string(),
                digest: PolicyDigestEntry {
                    algorithm: "sha384".to_string(),
                    value: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest),
                },
            });
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
    use assert_json_diff::assert_json_eq;
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
        assert_eq!(expected_digest, res["default_policy"].0);
        assert_json_eq!(json!({"allow":true}), res["default_policy"].1);

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

        let input = SetPolicyInput {
            r#type: "rego".to_string(),
            policy_id: "test".to_string(),
            policy: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy),
        };

        assert!(opa.set_policy(input).await.is_ok());
        let policy_list = opa.list_policies().await.unwrap();
        assert_eq!(policy_list.len(), 2);
        let test_policy = opa.get_policy("test".to_string()).await.unwrap();
        assert_eq!(test_policy, get_policy_output);
        assert!(opa.list_policies().await.is_ok());
    }
}
