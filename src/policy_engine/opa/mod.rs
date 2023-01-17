use crate::policy_engine::PolicyEngine;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::ffi::CStr;
use std::fs;
use std::os::raw::c_char;
use std::path::PathBuf;

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
    policy_file_path: PathBuf,
}

impl OPA {
    pub fn new(work_dir: PathBuf) -> Result<Self> {
        let mut policy_file_path = work_dir;

        policy_file_path.push("opa");
        if !policy_file_path.as_path().exists() {
            fs::create_dir_all(&policy_file_path)
                .map_err(|e| anyhow!("Create policy dir failed: {:?}", e))?;
        }

        policy_file_path.push("policy.rego");
        if !policy_file_path.as_path().exists() {
            let policy = std::include_str!("default_policy.rego").to_string();
            fs::write(&policy_file_path, policy)?;
        }

        Ok(Self { policy_file_path })
    }
}

impl PolicyEngine for OPA {
    fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
    ) -> Result<(bool, String)> {
        let policy = fs::read_to_string(&self.policy_file_path)
            .map_err(|e| anyhow!("Read OPA policy file failed: {:?}", e))?;

        let policy_go = GoString {
            p: policy.as_ptr() as *const i8,
            n: policy.len() as isize,
        };

        let reference = serde_json::json!({ "reference": reference_data_map }).to_string();

        let reference_go = GoString {
            p: reference.as_ptr() as *const i8,
            n: reference.len() as isize,
        };

        let input_go = GoString {
            p: input.as_ptr() as *const i8,
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

    #[test]
    fn test_evaluate() {
        let opa = OPA {
            policy_file_path: PathBuf::from("./src/policy_engine/opa/default_policy.rego"),
        };

        let reference_data: HashMap<String, Vec<String>> =
            serde_json::from_str(&dummy_reference(5)).unwrap();

        let res = opa.evaluate(reference_data.clone(), dummy_input(5, 5));
        assert!(res.is_ok(), "OPA execution() should be success");
        assert!(res.unwrap().0 == true, "allow should be true");

        let res = opa.evaluate(reference_data, dummy_input(0, 0));
        assert!(res.is_ok(), "OPA execution() should be success");
        assert!(res.unwrap().0 == false, "allow should be false");
    }
}
