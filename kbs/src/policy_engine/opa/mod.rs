// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::policy_engine::{PolicyEngineError, PolicyEngineInterface};
use async_trait::async_trait;
use base64::Engine;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Opa {
    policy_path: PathBuf,
}

impl Opa {
    pub fn new(policy_path: PathBuf) -> Result<Self, PolicyEngineError> {
        std::fs::create_dir_all(policy_path.parent().unwrap())?;

        if !policy_path.as_path().exists() {
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
        resource_path: &str,
        input_claims: &str,
    ) -> Result<bool, PolicyEngineError> {
        let mut engine = regorus::Engine::new();

        // Add policy as data
        engine
            .add_policy_from_file(self.policy_path.clone())
            .map_err(|_| PolicyEngineError::PolicyLoadError)?;

        // Add resource path as data
        let resource_path_object =
            regorus::Value::from_json_str(&format!("{{\"resource-path\":\"{}\"}}", resource_path))
                .map_err(|_| PolicyEngineError::ResourcePathError)?;

        engine
            .add_data(resource_path_object)
            .map_err(|_| PolicyEngineError::DataLoadError)?;

        // Add TCB claims as input
        engine
            .set_input_json(input_claims)
            .map_err(|_| PolicyEngineError::InputError)?;

        let res = engine.eval_bool_query("data.policy.allow".to_string(), false)?;
        Ok(res)
    }

    async fn set_policy(&mut self, policy: &str) -> Result<(), PolicyEngineError> {
        let policy_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(policy)?;

        tokio::fs::write(&self.policy_path, policy_bytes).await?;

        Ok(())
    }

    async fn get_policy(&self) -> Result<String, PolicyEngineError> {
        let policy = tokio::fs::read(&self.policy_path).await?;
        let policy = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(policy);
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use rstest::rstest;
    use serde_json::json;
    use tempfile::{NamedTempFile, TempDir};

    fn compare_errors(a: PolicyEngineError, b: PolicyEngineError) -> bool {
        match (a, b) {
            (PolicyEngineError::EvaluationError(_a), PolicyEngineError::EvaluationError(_b)) => {
                true
            }
            (PolicyEngineError::DataLoadError, PolicyEngineError::DataLoadError) => true,
            (PolicyEngineError::ResourcePathError, PolicyEngineError::ResourcePathError) => true,
            (PolicyEngineError::IOError(_a), PolicyEngineError::IOError(_b)) => true,
            (PolicyEngineError::DecodeError(_a), PolicyEngineError::DecodeError(_b)) => true,
            (PolicyEngineError::InputError, PolicyEngineError::InputError) => true,
            (PolicyEngineError::PolicyLoadError, PolicyEngineError::PolicyLoadError) => true,
            _ => false,
        }
    }

    fn dummy_input(product_id: &str, svn: u64) -> String {
        json!({
            "tee": "sample",
            "tee-pubkey": "dummy-key",
            "tcb-status": {
                "productId": product_id,
                "svn": svn
            }
        })
        .to_string()
    }

    async fn set_policy_from_file(opa: &mut Opa, path: &str) -> Result<(), PolicyEngineError> {
        let policy = std::fs::read(PathBuf::from(path.to_string())).unwrap();
        let policy = URL_SAFE_NO_PAD.encode(policy);

        opa.set_policy(&policy).await
    }

    #[tokio::test]
    async fn test_set_policy() {
        let tmp_dir = TempDir::new().unwrap();
        let tmp_file = tmp_dir.path().join("policy.rego");
        let mut opa = Opa::new(tmp_file).unwrap();

        set_policy_from_file(&mut opa, "test/data/policy_1.rego")
            .await
            .unwrap();

        // decode error
        let malformed_policy = "123";
        let res = opa.set_policy(malformed_policy).await;
        assert!(matches!(
            res.err().unwrap(),
            PolicyEngineError::DecodeError(base64::DecodeError::InvalidLastSymbol(_, _))
        ));

        // IOError
        drop(tmp_dir);
        let res = set_policy_from_file(&mut opa, "test/data/policy_1.rego").await;
        assert!(matches!(res.err().unwrap(), PolicyEngineError::IOError(_)));
    }

    #[rstest]
    #[case("test/data/policy_1.rego", "my_repo/Alice/key", "Alice", 1, Ok(true))]
    #[case("test/data/policy_4.rego", "my_repo/Alice/key", "Alice", 1, Ok(true))]
    #[case("test/data/policy_1.rego", "my_repo/Alice/key", "Bob", 1, Ok(false))]
    #[case("test/data/policy_3.rego", "my_repo/Alice/key", "Alice", 1, Ok(false))]
    #[case(
        "test/data/policy_1.rego",
        "\"",
        "",
        1,
        Err(PolicyEngineError::ResourcePathError)
    )]
    #[case(
        "test/data/policy_invalid_1.rego",
        "my_repo/Alice/key",
        "Alice",
        1,
        Err(PolicyEngineError::PolicyLoadError)
    )]
    #[case(
        "test/data/policy_invalid_2.rego",
        "my_repo/Alice/key",
        "Alice",
        1,
        Err(PolicyEngineError::EvaluationError(anyhow::anyhow!("test")))
    )]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret1", "n", 2, Ok(true))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret1", "n", 1, Ok(false))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret2", "n", 3, Ok(true))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret2", "n", 2, Ok(false))]
    #[case("test/data/policy_5.rego", "myrepo/secret/secret3", "n", 3, Ok(false))]
    #[case("test/data/policy_5.rego", "a/b/secret2", "n", 3, Ok(false))]
    #[case("test/data/policy_5.rego", "abc", "n", 3, Ok(false))]
    #[tokio::test]
    async fn test_evaluate(
        #[case] policy_path: &str,
        #[case] resource_path: &str,
        #[case] input_name: &str,
        #[case] input_svn: u64,
        #[case] expected: Result<bool, PolicyEngineError>,
    ) {
        let tmp_file = NamedTempFile::new().unwrap();
        let mut opa = Opa::new(tmp_file.path().to_path_buf()).unwrap();

        set_policy_from_file(&mut opa, policy_path).await.unwrap();

        let res = opa
            .evaluate(resource_path, &dummy_input(input_name, input_svn))
            .await;

        if let Ok(actual) = res {
            assert_eq!(
                actual,
                expected.expect("Result is Ok, but test expects Err")
            );
        } else if let Err(actual) = res {
            assert!(compare_errors(
                actual,
                expected.err().expect("Result is Err, but test expects Ok"),
            ));
        }
    }
}
