// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jwk::JwkAttestationTokenVerifier;
use kbs_types::TeePubKey;
use log::debug;
use serde::Deserialize;
use serde_json::Value;

mod error;
pub(crate) mod jwk;
pub use error::*;

pub const TOKEN_TEE_PUBKEY_PATH_ITA: &str = "/attester_runtime_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_COCO: &str = "/customized_claims/runtime_data/tee-pubkey";

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

    /// Trusted Certificates file (PEM format) paths use to verify Attestation
    /// Token Signature.
    #[serde(default)]
    pub trusted_certs_paths: Vec<String>,

    /// Urls (file:// and https:// schemes accepted) pointing to a local JWKSet file
    /// or to an OpenID configuration url giving a pointer to JWKSet certificates
    /// (for "Jwk") to verify Attestation Token Signature.
    #[serde(default)]
    pub trusted_jwk_sets: Vec<String>,

    /// Whether a JWK that directly comes from the JWT token is allowed to verify
    /// the signature. This is insecure as it will not check the endorsement of
    /// the JWK. If this option is set to false, the JWK will be looked up from
    /// the key store configured during launching the KBS with kid field in the JWT,
    /// or be checked against the configured trusted CA certs.
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
        extra_teekey_paths.push(TOKEN_TEE_PUBKEY_PATH_COCO.into());

        Ok(Self {
            verifier,
            extra_teekey_paths,
        })
    }

    /// Different attestation service would embed tee public key
    /// in different parts of the claims.
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
