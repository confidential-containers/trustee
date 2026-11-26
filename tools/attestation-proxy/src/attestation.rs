// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use anyhow::{Context, Result};
use kbs::token::{AttestationTokenVerifierConfig, TokenVerifier};
use key_value_storage::memory::MemoryKeyValueStorage;
use policy_engine::{PolicyEngine, rego::Regorus};
use serde_json::Value;

use crate::config::PolicyConfig;
use crate::error::AttestationError;

const POLICY_ID: &str = "proxy";
const ALLOW_RULE: &str = "data.policy.allow";

#[derive(Clone)]
pub struct AttestationVerifier {
    token_verifier: TokenVerifier,
    policy_engine: PolicyEngine<Regorus>,
}

impl AttestationVerifier {
    pub async fn new(config: AttestationTokenVerifierConfig, policy: PolicyConfig) -> Result<Self> {
        let token_verifier = TokenVerifier::from_config(config)
            .await
            .context("failed to initialize the token verifier")?;
        let source = std::fs::read_to_string(&policy.path)
            .with_context(|| format!("failed to read policy {}", policy.path.display()))?;
        let policy_engine = PolicyEngine::new(Arc::new(MemoryKeyValueStorage::default()));
        policy_engine
            .set_policy(POLICY_ID, &source, false)
            .await
            .context("invalid authorization policy")?;
        Ok(Self {
            token_verifier,
            policy_engine,
        })
    }

    pub async fn verify(&self, token: &str) -> Result<(), AttestationError> {
        let claims = self
            .token_verifier
            .verify(token.to_owned())
            .map_err(AttestationError::InvalidToken)?;
        let result = self
            .policy_engine
            .evaluate_rego(
                None,
                claims.to_string(),
                POLICY_ID,
                vec![ALLOW_RULE.to_string()],
                vec![],
            )
            .await
            .map_err(AttestationError::PolicyEvaluation)?;
        if result
            .eval_rules_result
            .get(ALLOW_RULE)
            .and_then(Option::as_ref)
            != Some(&Value::Bool(true))
        {
            return Err(AttestationError::PolicyDenied(
                "data.policy.allow did not return true".to_string(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use serde_json::{Value, json};

    use super::*;

    fn package() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }

    fn claims(tee: &str) -> Value {
        json!({
            "iss": "CoCo-Attestation-Service",
            "eat_profile": "tag:github.com,2024:confidential-containers/Trustee",
            "exp": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600,
            "submods": {"cpu0": {
                "ear_status": "affirming",
                "ear_attester_claims": {"tee": tee},
                "ear_appraisal_policy_ids": ["default"]
            }}
        })
    }

    fn token(claims: &Value) -> String {
        // Reuse Trustee's public signing-key and certificate fixtures.
        let jwks: Value = serde_json::from_str(include_str!(
            "../../../attestation-service/tests/fixtures/jwk/expected-jwks.json"
        ))
        .unwrap();
        let mut header = Header::new(Algorithm::ES256);
        header.jwk = Some(serde_json::from_value(jwks["keys"][0].clone()).unwrap());
        let key = EncodingKey::from_ec_pem(include_bytes!(
            "../../../attestation-service/tests/fixtures/jwk/signing-key.pem"
        ))
        .unwrap();
        encode(&header, claims, &key).unwrap()
    }

    async fn verifier(path: &Path) -> Result<AttestationVerifier> {
        let config = serde_json::from_value(json!({
            "trusted_certs_paths": [package().join(
                "../../attestation-service/tests/fixtures/jwk/cert-chain.pem"
            )]
        }))?;
        AttestationVerifier::new(config, PolicyConfig { path: path.into() }).await
    }

    #[tokio::test]
    async fn signed_tokens_must_satisfy_the_kbs_affirming_policy() {
        let verifier = verifier(&package().join("../../kbs/sample_policies/affirming.rego"))
            .await
            .unwrap();
        let mut claims = claims("sample");
        verifier.verify(&token(&claims)).await.unwrap();

        claims["submods"]["gpu0"] = json!({"ear_status": "warning"});
        assert_eq!(
            verifier
                .verify(&token(&claims))
                .await
                .unwrap_err()
                .status_code(),
            403
        );

        claims["submods"] = json!({});
        assert_eq!(
            verifier
                .verify(&token(&claims))
                .await
                .unwrap_err()
                .status_code(),
            403
        );
    }

    #[tokio::test]
    async fn token_authentication_precedes_even_an_allow_all_policy() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.rego");
        std::fs::write(&path, "package policy\nallow := true").unwrap();
        let verifier = verifier(&path).await.unwrap();
        let valid = token(&claims("sample"));
        verifier.verify(&valid).await.unwrap();

        let (signed_part, signature) = valid.rsplit_once('.').unwrap();
        let different = if signature.starts_with('A') { 'B' } else { 'A' };
        let tampered = format!("{signed_part}.{different}{}", &signature[1..]);
        assert_eq!(
            verifier.verify(&tampered).await.unwrap_err().status_code(),
            401
        );

        let mut expired = claims("sample");
        expired["exp"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                - 120
        );
        assert_eq!(
            verifier
                .verify(&token(&expired))
                .await
                .unwrap_err()
                .status_code(),
            401
        );
    }

    #[tokio::test]
    async fn policies_fail_closed_and_invalid_files_prevent_startup() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("policy.rego");
        assert!(verifier(&path).await.is_err());
        std::fs::write(&path, "this is not a Rego policy").unwrap();
        assert!(verifier(&path).await.is_err());

        for rule in ["allow := false", "allow := 1", "unrelated := true"] {
            std::fs::write(&path, format!("package policy\n{rule}")).unwrap();
            let verifier = verifier(&path).await.unwrap();
            assert_eq!(
                verifier
                    .verify(&token(&claims("tdx")))
                    .await
                    .unwrap_err()
                    .status_code(),
                403
            );
        }

        // Conflicting decisions cause an evaluation error; they must block access.
        std::fs::write(
            &path,
            "package policy\nimport rego.v1\nallow := true if { input.iss }\nallow := false if { input.iss }",
        )
        .unwrap();
        let verifier = verifier(&path).await.unwrap();
        assert_eq!(
            verifier
                .verify(&token(&claims("tdx")))
                .await
                .unwrap_err()
                .status_code(),
            503
        );
    }
}
