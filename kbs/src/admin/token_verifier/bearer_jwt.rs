// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This module implements the BearerJwt token verifier.

use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::Deserialize;
use std::path::PathBuf;
use tracing::info;

use crate::admin::{error::*, token_verifier::TokenVerifierTrait, Claims};

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct BearerJwtConfig {
    pub signer_pairs: Vec<IssuerConfig>,
}

/// A signer pair is public key used to verify the token and
/// an ID to decribe the signer.
///
/// The public key is now only supported for Ed25519 keys.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct IssuerConfig {
    pub issuer: String,
    pub public_key_path: PathBuf,
}

pub struct BearerJwtTokenVerifier {
    signer_pairs: Vec<Issuer>,
}

pub struct Issuer {
    issuer: String,
    public_key: DecodingKey,
}

impl BearerJwtTokenVerifier {
    pub fn new(config: BearerJwtConfig) -> Result<Self> {
        let mut signer_pairs = Vec::new();

        for signer_config in &config.signer_pairs {
            let user_public_key_pem = std::fs::read(&signer_config.public_key_path)?;

            // Try to parse the public key as an EC, RSA or ED key.
            let public_key = if let Ok(key) = DecodingKey::from_ec_pem(&user_public_key_pem) {
                key
            } else if let Ok(key) = DecodingKey::from_rsa_pem(&user_public_key_pem) {
                key
            } else {
                DecodingKey::from_ed_pem(&user_public_key_pem)?
            };

            signer_pairs.push(Issuer {
                issuer: signer_config.issuer.clone(),
                public_key,
            });
        }

        Ok(BearerJwtTokenVerifier { signer_pairs })
    }
}

impl TokenVerifierTrait for BearerJwtTokenVerifier {
    fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims> {
        let bearer = Authorization::<Bearer>::parse(request)?.into_scheme();
        let token = bearer.token();

        let header = decode_header(token)?;
        let validation = Validation::new(header.alg);
        for signer in &self.signer_pairs {
            if let Ok(jwt) = decode::<Claims>(token, &signer.public_key, &validation) {
                info!("Admin access granted for {}", signer.issuer);
                return Ok(jwt.claims);
            }
        }

        Err(Error::AdminAccessDenied {
            reason: "Cannot verify token with any of the issuers".to_string(),
        })
    }
}
