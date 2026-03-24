// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jwk::JwkAttestationTokenVerifier;
use serde::Deserialize;
use serde_json::Value;

mod error;
pub(crate) mod jwk;
pub use error::*;

/// TODO: handle this with attestation service backend
pub const TOKEN_TEE_PUBKEY_PATH_VALUE: &str = "/tee-pubkey";

#[derive(Deserialize, Debug, Clone, PartialEq, Default)]
pub struct AttestationTokenVerifierConfig {
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

        Ok(Self { verifier })
    }
}
