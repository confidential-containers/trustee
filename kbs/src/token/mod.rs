// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jwk::JwkAttestationTokenVerifier;
use kbs_types::TeePubKey;
use serde::Deserialize;
use serde_json::Value;
use tracing::debug;

mod error;
pub(crate) mod jwk;
pub use error::*;

pub const TOKEN_TEE_PUBKEY_PATH_ITA: &str = "/tdx/attester_runtime_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_ITA_VTPM: &str = "/tdx/attester_user_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_COCO: &str = "/customized_claims/runtime_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_EAR: &str =
    "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_VALUE: &str = "/tee-pubkey";

#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct AttestationTokenVerifierConfig {
    #[serde(default)]
    /// The paths to the tee public key in the JWT body. For example,
    /// `/attester_runtime_data/tee-pubkey` refers to the key
    /// `attester_runtime_data.tee-pubkey` inside the JWT body claims.
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

    /// Whether the token signing key is (not) validated.
    /// If true, the attestation token can be modified in flight.
    /// This should only be set to true for testing.
    /// While the token signature is still validated, the provenance of the
    /// signing key is not checked and the key could be replaced.
    ///
    /// When false, the key must be endorsed by the certificates or JWK sets
    /// specified above.
    ///
    /// Default: false
    #[serde(default = "bool::default")]
    pub insecure_key: bool,
}

#[derive(Clone)]
pub struct TokenVerifier {
    verifier: JwkAttestationTokenVerifier,
    extra_teekey_paths: Vec<String>,
}

impl TokenVerifier {
    pub async fn verify(&self, token: String) -> Result<Value> {
        self.verifier
            .verify(token)
            .await
            .map_err(|e| Error::TokenVerificationFailed { source: e })
    }

    pub async fn from_config(config: AttestationTokenVerifierConfig) -> Result<Self> {
        let verifier = JwkAttestationTokenVerifier::new(&config)
            .await
            .map_err(|e| Error::TokenVerifierInitialization { source: e })?;

        let mut extra_teekey_paths = config.extra_teekey_paths;
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_ITA.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_ITA_VTPM.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_COCO.into());
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_EAR.into());
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
            if let Some(pkey_value) = claim.pointer(path) {
                debug!("Extract tee public key from {path}");
                return TeePubKey::deserialize(pkey_value).map_err(|_| Error::TeePubKeyParseFailed);
            }
        }

        Err(Error::NoTeePubKeyClaimFound)
    }
}
