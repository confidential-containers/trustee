// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::token::{AttestationTokenVerifier, AttestationTokenVerifierConfig};
use anyhow::*;
use async_trait::async_trait;
use ear::Ear;
use jsonwebtoken::DecodingKey;

pub struct EarAttestationTokenVerifier {
    public_key_bytes: Vec<u8>,
}

impl EarAttestationTokenVerifier {
    pub fn new(config: &AttestationTokenVerifierConfig) -> Result<Self> {
        let public_key_path = match config.trusted_certs_paths.len() {
            1 => &config.trusted_certs_paths[0],
            _ => bail!("One public key path is expected for EAR token verifier"),
        };

        let public_key_bytes = std::fs::read(public_key_path)?;

        Ok(Self { public_key_bytes })
    }
}

#[async_trait]
impl AttestationTokenVerifier for EarAttestationTokenVerifier {
    async fn verify(&self, token: String) -> Result<String> {
        let public_key = DecodingKey::from_ec_pem(&self.public_key_bytes)?;
        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key)?;

        ear.validate()?;

        Ok(serde_json::to_string(&ear)?)
    }
}
