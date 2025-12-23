// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This module implements the BearerJwt token verifier.

use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};

use serde::Deserialize;
use serde_json::Value;
use tracing::{debug, error, info, warn};

use crate::admin::{authentication::TokenVerifierTrait, error::*, Claims};
use crate::crypto::jwt::JwtVerifier;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct BearerJwtConfig {
    pub identity_providers: Vec<IssuerConfig>,
}

/// Issuer config used to verify admin JWT tokens.
///
/// - `public_key_uri`: a PEM file source (`https://`, `file://`, local path)
/// - `jwk_set_uri`: a JWKS source (https://, file:// or local path)
/// - `issuer`: the issuer of the JWT token. If given, This field will be checked when a token is verified successfully
///   with given public key or JWKS. If the token's issuer is matched, the token will be verified successfully.
/// - `audience`: the audience of the JWT token. If given, This field will be checked when a token is verified successfully
///   with given public key or JWKS. If any of the token's audiences is matched, the token will be verified successfully.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    pub public_key_uri: Option<String>,
    pub jwk_set_uri: Option<String>,
}

struct TrustedIssuer {
    issuer: Option<String>,
    audience: Option<String>,
    verifier: JwtVerifier,
}

pub struct BearerJwtTokenVerifier {
    trusted_issuers: Vec<TrustedIssuer>,
}

struct StandardTokenClaims {
    issuer: String,
    audiences: Vec<String>,
}

impl BearerJwtTokenVerifier {
    pub async fn new(config: BearerJwtConfig) -> Result<Self> {
        let mut trusted_issuers = Vec::new();

        for idp_config in config.identity_providers {
            let issuer = idp_config.issuer;
            let trusted_pem_public_key_uris: Vec<String> =
                idp_config.public_key_uri.into_iter().collect();
            let trusted_jwk_set_uris: Vec<String> = idp_config.jwk_set_uri.into_iter().collect();

            let verifier = JwtVerifier::new(
                &trusted_jwk_set_uris,
                &[],
                &trusted_pem_public_key_uris,
                false,
            )
            .await
            .map_err(|e| Error::InvalidTokenVerifierConfig(e.to_string()))?;
            trusted_issuers.push(TrustedIssuer {
                issuer,
                audience: idp_config.audience,
                verifier,
            });
        }

        Ok(BearerJwtTokenVerifier { trusted_issuers })
    }
}

impl TokenVerifierTrait for BearerJwtTokenVerifier {
    fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims> {
        let bearer = Authorization::<Bearer>::parse(request)?.into_scheme();
        let token = bearer.token();

        for trusted_issuer in &self.trusted_issuers {
            let Ok(raw_claims) = trusted_issuer.verifier.verify(token) else {
                debug!(issuer =? trusted_issuer.issuer, "Failed to verify token");
                continue;
            };
            let standard_claims =
                standard_claims_from_value(&raw_claims).map_err(|e| Error::AdminAccessDenied {
                    reason: format!("Failed to parse standard claims from token: {e:?}"),
                })?;
            let claims = claims_from_value(raw_claims).map_err(|e| Error::AdminAccessDenied {
                reason: format!("Failed to parse claims from token: {e:?}"),
            })?;

            if let Some(issuer) = &trusted_issuer.issuer {
                if standard_claims.issuer != *issuer {
                    error!(
                        "A token can be verified with public key, but the token issuer mismatch: expected {issuer}, got {claims_issuer}. Try the next issuer.",
                        claims_issuer = standard_claims.issuer
                    );
                    continue;
                }
            } else {
                warn!(
                    "The issuer is not set in the `trusted_issuers` config, skipping issuer check."
                );
            }

            if let Some(audience) = &trusted_issuer.audience {
                if !standard_claims.audiences.contains(audience) {
                    error!(
                        "A token can be verified with public key, but the token audience mismatch: expected {audience}, got {:?}. Try the next issuer.",
                        standard_claims.audiences
                    );
                    continue;
                }
            } else {
                warn!(
                    "The audience is not set in the `trusted_issuers` config, skipping audience check."
                );
            }

            info!("Endorsement of a token has been verified successfully. Continue to check the authorization.");
            debug!("Admin claims: {:?}", claims);
            return Ok(claims);
        }

        Err(Error::AdminAccessDenied {
            reason: "Cannot verify token with any of the issuers".to_string(),
        })
    }
}

fn standard_claims_from_value(value: &Value) -> Result<StandardTokenClaims> {
    let issuer = value
        .get("iss")
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

    Ok(StandardTokenClaims { issuer, audiences })
}

fn claims_from_value(value: Value) -> Result<Claims> {
    let role = value
        .get("role")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::AdminAccessDenied {
            reason: "Missing required `role` claim in JWT".to_string(),
        })?
        .to_string();

    Ok(Claims { role })
}
