// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs_types::TeePubKey;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

use crate::crypto::jwt::JwtVerifier;

mod error;
pub use error::*;

pub const TOKEN_TEE_PUBKEY_PATH_ITA: &str = "/tdx/attester_runtime_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_ITA_VTPM: &str = "/tdx/attester_user_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_COCO: &str = "/customized_claims/runtime_data/tee-pubkey";

/// This is the legacy path for the EAR tee public key of EAR token before ID-4 version.
/// TODO: Remove this when proper.
pub const TOKEN_TEE_PUBKEY_PATH_EAR_LEGACY: &str =
    "/submods/*/ear.veraison.annotated-evidence/runtime_data_claims/tee-pubkey";

pub const TOKEN_TEE_PUBKEY_PATH_EAR: &str =
    "/submods/*/ear_verifier_claims/runtime_data/tee-pubkey";
pub const TOKEN_INIT_DATA_PATH_EAR: &str = "/submods/*/ear_verifier_claims/init_data";
pub const TOKEN_TEE_PUBKEY_PATH_VALUE: &str = "/tee-pubkey";

#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct AttestationTokenVerifierConfig {
    #[serde(default)]
    /// The paths to the tee public key in the JWT body. For example,
    /// `/attester_runtime_data/tee-pubkey` refers to the key
    /// `attester_runtime_data.tee-pubkey` inside the JWT body claims.
    /// A path segment `*` matches every key of an object, the first match is
    /// used. See [`pointer`].
    ///
    /// If a JWT is received, the [`TokenVerifier`] will try to extract
    /// the tee public key from built-in ones ([`TOKEN_TEE_PUBKEY_PATH_ITA`],
    /// [`TOKEN_TEE_PUBKEY_PATH_COCO`]) and the configured `extra_teekey_paths`.
    ///
    /// This field will default to an empty vector.
    pub extra_teekey_paths: Vec<String>,

    /// File paths of trusted certificates in PEM format used to verify
    /// the signature of the Attestation Token.
    #[serde(default)]
    pub trusted_certs_paths: Vec<String>,

    /// URLs (file:// and https:// schemes accepted) pointing to a local JWKSet file
    /// or to an OpenID configuration url giving a pointer to JWKSet certificates
    /// (for "Jwk") to verify Attestation Token Signature.
    #[serde(default)]
    pub trusted_jwk_sets: Vec<String>,

    /// Whether to skip endorsement checks for a JWK embedded in the JWT header.
    ///
    /// When false (default) and the token header carries a `jwk`, the key must be
    /// backed by an `x5c` certificate chain that chains to [`trusted_certs_paths`].
    /// When true, that `jwk` is used directly to verify the signature without
    /// checking its provenance; the signature itself is still validated.
    ///
    /// This only affects header-embedded `jwk` keys. Tokens that identify the
    /// signing key via `kid` are still resolved from [`trusted_jwk_sets`].
    ///
    /// Should only be set to true for testing: an attacker who can replace the
    /// header `jwk` can make KBS accept tokens signed with an arbitrary key.
    ///
    /// Default: false
    #[serde(default = "bool::default")]
    pub insecure_header_jwk: bool,
}

/// Like [`Value::pointer`], but a segment `*` matches every key of an object
/// (in key order) and the first match wins.
///
/// An EAR token has one `submods` entry per policy, and the name of the entry
/// is chosen by the policy. So `/submods/*/ear_verifier_claims/init_data` is
/// the init data of the first submod that has any.
pub fn pointer<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    fn walk<'a>(value: &'a Value, segments: &[&str]) -> Option<&'a Value> {
        let Some((segment, rest)) = segments.split_first() else {
            return Some(value);
        };
        if *segment == "*" {
            return value
                .as_object()?
                .values()
                .find_map(|value| walk(value, rest));
        }
        // Same escaping as in `Value::pointer`.
        let segment = segment.replace("~1", "/").replace("~0", "~");
        match value {
            Value::Object(map) => map.get(&segment),
            Value::Array(list) => segment.parse::<usize>().ok().and_then(|i| list.get(i)),
            _ => None,
        }
        .and_then(|value| walk(value, rest))
    }

    if path.is_empty() {
        return Some(value);
    }
    walk(
        value,
        &path.strip_prefix('/')?.split('/').collect::<Vec<_>>(),
    )
}

#[derive(Clone)]
pub struct TokenVerifier {
    verifier: JwtVerifier,
    extra_teekey_paths: Vec<String>,
}

impl TokenVerifier {
    pub fn verify(&self, token: String) -> Result<Value> {
        self.verifier
            .verify(&token)
            .map_err(|e| Error::TokenVerificationFailed { source: e })
    }

    pub async fn from_config(config: AttestationTokenVerifierConfig) -> Result<Self> {
        let verifier = JwtVerifier::new(
            &config.trusted_jwk_sets,
            &config.trusted_certs_paths,
            &Vec::new(),
            config.insecure_header_jwk,
        )
        .await
        .map_err(|e| Error::TokenVerifierInitialization { source: e })?;

        let mut extra_teekey_paths = config.extra_teekey_paths;
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_ITA.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_ITA_VTPM.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_COCO.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_EAR.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_EAR_LEGACY.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_VALUE.into());

        Ok(Self {
            verifier,
            extra_teekey_paths,
        })
    }

    /// Different types of attestation tokens store the tee public key in
    /// different places.
    /// Try extracting the key from multiple built-in paths as well as any extras
    /// specified in the config file.
    pub fn extract_tee_public_key(&self, claim: Value) -> Result<TeePubKey> {
        for path in &self.extra_teekey_paths {
            if let Some(pkey_value) = pointer(&claim, path) {
                debug!("Extract tee public key from {path}");
                return TeePubKey::deserialize(pkey_value).map_err(|_| Error::TeePubKeyParseFailed);
            }
        }

        Err(Error::NoTeePubKeyClaimFound)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_pointer_matches_every_submod() {
        let claims = json!({"submods": {
            "cpu0": {"ear_verifier_claims": {"devices": ["tdx"]}},
            "tpm0": {"ear_verifier_claims": {"runtime_data": {"tee-pubkey": "key"}}},
        }});

        assert_eq!(
            pointer(&claims, TOKEN_TEE_PUBKEY_PATH_EAR),
            Some(&json!("key"))
        );
        assert_eq!(
            pointer(&claims, "/submods/*/ear_verifier_claims/devices"),
            Some(&json!(["tdx"]))
        );
        assert_eq!(
            pointer(&claims, "/submods/*/ear_verifier_claims/init_data"),
            None
        );
        assert_eq!(
            pointer(&claims, "/submods/cpu0/ear_verifier_claims/devices/0"),
            Some(&json!("tdx"))
        );
        // The paths without a wildcard behave as `Value::pointer` does.
        assert_eq!(
            pointer(&claims, "/submods/tpm0"),
            claims.pointer("/submods/tpm0")
        );
        assert_eq!(pointer(&claims, ""), Some(&claims));
        assert_eq!(pointer(&claims, "submods"), None);
    }

    #[test]
    fn test_pointer_uses_the_first_submod_that_matches() {
        let claims = json!({"submods": {
            "b": {"x": 2},
            "a": {"y": 0},
            "c": {"x": 3},
        }});
        // `serde_json` keeps the keys sorted.
        assert_eq!(pointer(&claims, "/submods/*/x"), Some(&json!(2)));
    }
}
