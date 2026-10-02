// Copyright (c) 2026 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Result, anyhow, bail};
use base64::Engine;
use serde::Deserialize;
use std::collections::HashMap;
use std::str::FromStr;

use crate::TeeEvidenceParsedClaim;

const OVERALL_RESULT_CLAIM: &str = "x-nvidia-overall-att-result";

/// Internal struct for deserializing a detached EAT.
/// The first element is a slice with two fields:
/// - The first field is "JWT" string
/// - The second field is the base64 encoded primary JWT
///
/// The second element is a HashMap with the device name as the
///   key and base64 encoded Individual JWTs as the value.
///
/// See the following link for more details
/// https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/introduction.html
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
struct DetachedEatInternal(Vec<String>, HashMap<String, String>);

/// Detached EAT as produced by NRAS and by the NVAT SDK.
#[derive(Clone, Debug, PartialEq)]
pub struct DetachedEat {
    overall_jwt: String,
    device_jwts: Vec<String>,
}

impl FromStr for DetachedEat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let eat: DetachedEatInternal = serde_json::from_str(s)?;

        if eat.0.len() != 2 {
            bail!("Unexpected Payload Format");
        };

        Ok(DetachedEat {
            overall_jwt: eat.0[1].clone(),
            device_jwts: eat.1.into_values().collect(),
        })
    }
}

impl DetachedEat {
    pub fn overall_jwt(&self) -> &str {
        &self.overall_jwt
    }

    pub fn device_jwts(&self) -> &[String] {
        &self.device_jwts
    }

    /// Extracts the claims of every device. If the overall token carries an
    /// overall attestation result, it is added to each device's claims.
    ///
    /// The tokens are not validated.
    pub fn claims(&self) -> Result<Vec<TeeEvidenceParsedClaim>> {
        let overall_result = get_jwt_payload(self.overall_jwt.clone())?
            .pointer(&format!("/{OVERALL_RESULT_CLAIM}"))
            .cloned();

        self.device_jwts
            .iter()
            .map(|jwt| {
                let mut claims = get_jwt_payload(jwt.clone())?;
                if let Some(overall_result) = &overall_result {
                    claims
                        .as_object_mut()
                        .ok_or_else(|| anyhow!("Unexpected claims format."))?
                        .insert(OVERALL_RESULT_CLAIM.to_string(), overall_result.clone());
                }
                Ok(claims)
            })
            .collect()
    }
}

pub fn get_jwt_payload(jwt: String) -> Result<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        bail!("Malformed JWT");
    }

    let b64_engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let payload_bytes = b64_engine.decode(parts[1])?;
    let payload_str = String::from_utf8_lossy(&payload_bytes);

    Ok(serde_json::from_str(&payload_str)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::{Value, json};

    fn fake_jwt(payload: &Value) -> String {
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
        let header = b64.encode(br#"{"alg":"none"}"#);
        let body = b64.encode(serde_json::to_vec(payload).unwrap());
        format!("{header}.{body}.sig")
    }

    #[rstest]
    #[case::one_device(json!({"GPU-0": fake_jwt(&json!({"a": 1}))}), 1)]
    #[case::two_devices(
        json!({
            "GPU-0": fake_jwt(&json!({"a": 1})),
            "GPU-1": fake_jwt(&json!({"a": 2}))
        }),
        2
    )]
    fn claims_are_extracted_per_device(#[case] devices: Value, #[case] count: usize) {
        let overall = fake_jwt(&json!({OVERALL_RESULT_CLAIM: true}));
        let eat: DetachedEat = json!([["JWT", overall], devices])
            .to_string()
            .parse()
            .unwrap();

        let claims = eat.claims().unwrap();
        assert_eq!(claims.len(), count);
        for claim in claims {
            assert_eq!(claim[OVERALL_RESULT_CLAIM], true);
        }
    }

    #[test]
    fn claims_without_overall_result_are_unchanged() {
        let overall = fake_jwt(&json!({}));
        let eat: DetachedEat = json!([["JWT", overall], {"GPU-0": fake_jwt(&json!({"a": 1}))}])
            .to_string()
            .parse()
            .unwrap();

        assert_eq!(eat.claims().unwrap(), vec![json!({"a": 1})]);
    }

    #[rstest]
    #[case::not_json("not json")]
    #[case::short_overall(r#"[["JWT"], {}]"#)]
    #[case::long_overall(r#"[["JWT", "a", "b"], {}]"#)]
    fn malformed_eat_is_rejected(#[case] input: &str) {
        assert!(input.parse::<DetachedEat>().is_err());
    }

    #[rstest]
    #[case::not_three_parts("a.b")]
    #[case::not_base64("a.!!!.c")]
    fn malformed_jwt_is_rejected(#[case] jwt: &str) {
        assert!(get_jwt_payload(jwt.to_string()).is_err());
    }

    #[test]
    fn non_object_device_claims_are_rejected_with_overall_result() {
        let overall = fake_jwt(&json!({OVERALL_RESULT_CLAIM: true}));
        let eat: DetachedEat = json!([["JWT", overall], {"GPU-0": fake_jwt(&json!([1]))}])
            .to_string()
            .parse()
            .unwrap();

        assert!(eat.claims().is_err());
    }
}
