// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::policy_engine::PolicyEngineInterface;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
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

#[derive(Debug, Clone)]
pub struct Opa {
    policy_path: PathBuf,
}

impl Opa {
    pub fn new(policy_path: PathBuf) -> Result<Self> {
        if !policy_path.as_path().exists() {
            if !policy_path.as_path().parent().unwrap().exists() {
                std::fs::create_dir_all(policy_path.parent().unwrap())?;
            }
            let policy = std::include_str!("default_policy.rego").to_string();
            fs::write(&policy_path, policy)?;
        }

        Ok(Self { policy_path })
    }
}

#[async_trait]
impl PolicyEngineInterface for Opa {
    async fn evaluate(
        &self,
        resource_path: String,
        input_claims: String,
    ) -> Result<(bool, String)> {
        let policy = tokio::fs::read_to_string(
            self.policy_path
                .to_str()
                .ok_or_else(|| anyhow!("Missing Policy Path"))?,
        )
        .await
        .map_err(|e| anyhow!("Reading OPA policy file failed: {:?}", e))?;

        let policy_go = GoString {
            p: policy.as_ptr() as *const c_char,
            n: policy.len() as isize,
        };

        let resource_path_input = serde_json::json!({ "resource-path": resource_path }).to_string();

        let resource_path_go = GoString {
            p: resource_path_input.as_ptr() as *const c_char,
            n: resource_path_input.len() as isize,
        };

        let input_go = GoString {
            p: input_claims.as_ptr() as *const c_char,
            n: input_claims.len() as isize,
        };

        // Call the function exported by cgo and process the returned decision
        let decision_buf: *mut c_char =
            unsafe { evaluateGo(policy_go, resource_path_go, input_go) };
        let decision_str: &CStr = unsafe { CStr::from_ptr(decision_buf) };
        let res = decision_str.to_str()?.to_string();
        log::debug!("Evaluated: {}", res);
        if res.starts_with("Error::") {
            return Err(anyhow!(res));
        }

        let res_kv: Value = serde_json::from_str(&res)?;
        let result_boolean = res_kv["allow"]
            .as_bool()
            .ok_or_else(|| anyhow!("Policy Engine output must contain \"allow\" boolean value"))?;

        Ok((result_boolean, res))
    }

    async fn set_policy(&mut self, policy: String) -> Result<()> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(policy)
            .map_err(|e| anyhow!("Base64 decode OPA policy string failed: {:?}", e))?;

        tokio::fs::write(&self.policy_path, policy_bytes)
            .await
            .map_err(|e| anyhow!("Write OPA policy to file failed: {:?}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use serde_json::json;

    fn dummy_input(product_id: &str, svn: u64) -> String {
        json!({
            "tee-pubkey": "dummy-key",
            "tcb-status": {
                "productId": product_id.to_string(),
                "svn": svn.to_string(),
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn test_evaluate() {
        let opa = Opa {
            policy_path: PathBuf::from("../../test/data/policy_1.rego"),
        };

        let resource_path = "my_repo/Alice/key".to_string();

        let res = opa
            .evaluate(resource_path.clone(), dummy_input("Alice", 1))
            .await;
        assert!(res.is_ok(), "OPA execution() should be success");
        assert!(res.unwrap().0 == true, "allow should be true");

        let res = opa.evaluate(resource_path, dummy_input("Bob", 1)).await;
        assert!(res.is_ok(), "OPA execution() should be success");
        assert!(res.unwrap().0 == false, "allow should be false");
    }

    #[tokio::test]
    async fn test_set_policy() {
        let mut opa = Opa::new(PathBuf::from("../../test/data/policy_2.rego")).unwrap();
        let policy_bytes = b"package policy
default allow = true";

        let policy = URL_SAFE_NO_PAD.encode(policy_bytes);

        assert!(opa.set_policy(policy).await.is_ok());
    }
}
