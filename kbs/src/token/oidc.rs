// Copyright (c) 2024 by Intel Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::token::{AttestationTokenVerifier, AttestationTokenVerifierConfig};
use anyhow::*;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Validation};
use reqwest::{get, Url};
use serde_json::Value;
use std::str::FromStr;

const OPENID_CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";

pub struct OidcAttestationTokenVerifier {
    trusted_certs: Option<jwk::JwkSet>,
}

impl OidcAttestationTokenVerifier {
    pub async fn new(config: &AttestationTokenVerifierConfig) -> Result<Self> {
        let trusted_certs = match &config.trusted_certs_paths {
            Some(paths) => {
                let mut keyset = jwk::JwkSet { keys: Vec::new() };

                for url in paths.iter() {
                    // TODO: accept both "local" jwks and OIDC ones
                    let oidc_url = Url::parse(url)?.join(OPENID_CONFIG_URL_SUFFIX)?;
                    let oidc_values = get(oidc_url).await?.json::<Value>().await?;

                    let jwks_uri = oidc_values["jwks_uri"].as_str().ok_or(anyhow!(
                        "Failed to parse jwks uri from OpenID Configuration"
                    ))?;

                    let jwkset = get(jwks_uri).await?.json::<jwk::JwkSet>().await?;

                    for jwk in jwkset.keys.iter() {
                        keyset.keys.push(jwk.clone());
                    }
                }
                Some(keyset)
            }
            None => None,
        };

        Ok(Self { trusted_certs })
    }
}

#[async_trait]
impl AttestationTokenVerifier for OidcAttestationTokenVerifier {
    async fn verify(&self, token: String) -> Result<String> {
        let header = decode_header(&token).context("Failed to decode attestation token header")?;

        let Some(keyset) = &self.trusted_certs else {
            bail!("missing config");
        };

        let kid = header
            .kid
            .ok_or(anyhow!("Failed to decode kid in the token header"))?;
        let key = keyset
            .find(&kid)
            .ok_or(anyhow!("Failed to find kid in trusted certificates"))?;

        let alg = Algorithm::from_str(key.common.key_algorithm.unwrap().to_string().as_str())?;

        let dkey = DecodingKey::from_jwk(key)?;
        let token_data = decode::<Value>(&token, &dkey, &Validation::new(alg))
            .context("Failed to decode attestation token")?;

        Ok(serde_json::to_string(&token_data.claims)?)
    }
}

// TODO: tests
