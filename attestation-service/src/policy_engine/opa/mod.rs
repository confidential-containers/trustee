use crate::policy_engine::{PolicyEngine, PolicyType};
use anyhow::{anyhow, bail, Result};
use as_types::SetPolicyInput;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;
use std::str::FromStr;

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
        policy_id: Option<String>,
    ) -> Result<(bool, String)> {
        let policy_file_path = format!(
            "{}/{}.rego",
            self.policy_dir_path
                .to_str()
                .ok_or_else(|| anyhow!("Miss Policy DirPath"))?,
            policy_id.unwrap_or("default".to_string())
        );
        let policy = tokio::fs::read_to_string(policy_file_path)
            .await
            .map_err(|e| anyhow!("Read OPA policy file failed: {:?}", e))?;

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
        let decision_buf: *mut c_char = unsafe { evaluateGo(policy_go, reference_go, input_go) };
        let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
        let res = decision_str.to_str()?.to_string();
        debug!("Evaluated: {}", res);
        if res.starts_with("Error::") {
            return Err(anyhow!(res));
        }

        let res_kv: Value = serde_json::from_str(&res)?;

        Ok((res_kv["allow"].as_bool().unwrap_or(false), res))
    }

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()> {
        let policy_type = PolicyType::from_str(&input.r#type)
            .map_err(|_| anyhow!("{} is not support by AS", &input.r#type))?;
        if policy_type != PolicyType::Rego {
            bail!("OPA Policy Engine only support .rego policy");
        }

        let policy_bytes = base64::decode_config(input.policy, base64::URL_SAFE_NO_PAD)
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
                Some(default_policy_id.clone()),
            )
            .await;
        assert!(res.is_ok(), "OPA execution() should be success");
        assert!(res.unwrap().0 == true, "allow should be true");

        let res = opa
            .evaluate(reference_data, dummy_input(0, 0), Some(default_policy_id))
            .await;
        assert!(res.is_ok(), "OPA execution() should be success");
        assert!(res.unwrap().0 == false, "allow should be false");
    }

    #[tokio::test]
    async fn test_set_policy() {
        let mut opa = OPA::new(PathBuf::from("./test_data")).unwrap();
        let policy = "package policy
default allow = true"
            .to_string();

        let input = SetPolicyInput {
            r#type: "rego".to_string(),
            policy_id: "test".to_string(),
            policy: base64::encode_config(policy, base64::URL_SAFE_NO_PAD),
        };

        assert!(opa.set_policy(input).await.is_ok());
    }
}
