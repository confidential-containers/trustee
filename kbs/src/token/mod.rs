// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;
use std::sync::Arc;
use strum::EnumString;
use tokio::sync::RwLock;

mod coco;
pub(crate) mod jwk;

#[async_trait]
pub trait AttestationTokenVerifier {
    /// Verify an signed attestation token.
    /// Returns the custom claims JSON string of the token.
    async fn verify(&self, token: String) -> Result<String>;
}

#[derive(Deserialize, Default, Debug, Clone, EnumString)]
pub enum AttestationTokenVerifierType {
    #[default]
    CoCo,
    Jwk,
}

#[derive(Deserialize, Debug, Clone)]
pub struct AttestationTokenVerifierConfig {
    #[serde(default)]
    pub attestation_token_type: AttestationTokenVerifierType,

    /// Trusted Certificates file (PEM format) path (for "CoCo") or a valid Url
    /// (file:// and https:// schemes accepted) pointing to a local JWKSet file
    /// or to an OpenID configuration url giving a pointer to JWKSet certificates
    /// (for "Jwk") to verify Attestation Token Signature.
    #[serde(default)]
    pub trusted_certs_paths: Vec<String>,
}

pub async fn create_token_verifier(
    config: AttestationTokenVerifierConfig,
) -> Result<Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>> {
    match config.attestation_token_type {
        AttestationTokenVerifierType::CoCo => Ok(Arc::new(RwLock::new(
            coco::CoCoAttestationTokenVerifier::new(&config)?,
        ))
            as Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>),
        AttestationTokenVerifierType::Jwk => Ok(Arc::new(RwLock::new(
            jwk::JwkAttestationTokenVerifier::new(&config).await?,
        ))
            as Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>),
    }
}
