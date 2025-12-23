// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This module implements the BearerJwt token verifier.

use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};

use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use tracing::{error, info};

use crate::admin::{error::*, token_verifier::TokenVerifierTrait, Claims};
use crate::crypto::jwt::JwtVerifier;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct BearerJwtConfig {
    pub idps: Vec<IssuerConfig>,
    /// Allow loading admin PEM keys from plaintext HTTP sources.
    /// Keep disabled by default and only enable in controlled environments.
    pub insecure_public_key_from_uri: bool,
}

/// Issuer config used to verify admin JWT tokens.
///
/// Use one of:
/// - `public_key_uri`: a PEM file source (`https://`, `file://`, local path,
///   or `http://` when `insecure_public_key_from_uri=true`)
/// - `jwk_set_uri`: a JWKS source (https://, file:// or local path)
///
/// If both are provided, `public_key_uri` is used first.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct IssuerConfig {
    pub issuer: String,
    pub public_key_uri: Option<String>,
    pub jwk_set_uri: Option<String>,
}

pub struct BearerJwtTokenVerifier {
    trusted_issuers: BTreeMap<String, JwtVerifier>,
}

impl BearerJwtTokenVerifier {
    pub async fn new(config: BearerJwtConfig) -> Result<Self> {
        let mut trusted_issuers = BTreeMap::new();

        for signer_config in config.idps {
            let issuer = signer_config.issuer;
            let trusted_pem_public_key_uris: Vec<String> =
                signer_config.public_key_uri.into_iter().collect();
            let trusted_jwk_set_uris: Vec<String> = signer_config.jwk_set_uri.into_iter().collect();

            let verifier = JwtVerifier::new(
                &trusted_jwk_set_uris,
                &[],
                &trusted_pem_public_key_uris,
                false,
                config.insecure_public_key_from_uri,
            )
            .await
            .map_err(|e| Error::InvalidTokenVerifierConfig(e.to_string()))?;
            trusted_issuers.insert(issuer, verifier);
        }

        Ok(BearerJwtTokenVerifier { trusted_issuers })
    }
}

impl TokenVerifierTrait for BearerJwtTokenVerifier {
    fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims> {
        let bearer = Authorization::<Bearer>::parse(request)?.into_scheme();
        let token = bearer.token();

        for (issuer, verifier) in &self.trusted_issuers {
            match verifier.verify(token) {
                Ok(raw_claims) => match claims_from_value(raw_claims) {
                    Ok(claims) => {
                        info!("Admin access check for a token from {} succeeded.", issuer);
                        info!("Admin claims: {:?}", claims);
                        return Ok(claims);
                    }
                    Err(e) => {
                        error!("Failed to parse claims from token: {:?}", e);
                        continue;
                    }
                },
                Err(e) => error!("Failed to verify token: {:?}", e),
            }
        }
        Err(Error::AdminAccessDenied {
            reason: "Cannot verify token with any of the issuers".to_string(),
        })
    }
}

fn claims_from_value(value: Value) -> Result<Claims> {
    let issuer = value
        .get("iss")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let subject = value
        .get("sub")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let audiences = match value.get("aud") {
        Some(Value::String(aud)) => vec![aud.clone()],
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    };

    Ok(Claims {
        issuer,
        subject,
        audiences,
    })
}
