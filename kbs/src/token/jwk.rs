// Copyright (c) 2024 by Intel Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::token::{AttestationTokenVerifier, AttestationTokenVerifierConfig};
use anyhow::*;
use async_trait::async_trait;
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Validation};
use reqwest::{get, Url};
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::result::Result::Ok;
use std::str::FromStr;
use thiserror::Error;

const OPENID_CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";

#[derive(Error, Debug)]
pub enum JwksGetError {
    #[error("Invalid source path: {0}")]
    InvalidSourcePath(String),
    #[error("Failed to access source: {0}")]
    AccessFailed(String),
    #[error("Failed to deserialize source data: {0}")]
    DeserializeSource(String),
}

#[derive(Deserialize)]
struct OpenIDConfig {
    jwks_uri: String,
}

pub struct JwkAttestationTokenVerifier {
    trusted_certs: jwk::JwkSet,
}

pub async fn get_jwks_from_file_or_url(p: &str) -> Result<jwk::JwkSet, JwksGetError> {
    let mut url = Url::parse(p).map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;
    match url.scheme() {
        "https" => {
            url.set_path(OPENID_CONFIG_URL_SUFFIX);

            let oidc = get(url.as_str())
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                .json::<OpenIDConfig>()
                .await
                .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))?;

            let jwkset = get(oidc.jwks_uri)
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                .json::<jwk::JwkSet>()
                .await
                .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))?;

            Ok(jwkset)
        }
        "file" => {
            let file = File::open(url.path())
                .map_err(|e| JwksGetError::AccessFailed(format!("open {}: {}", url.path(), e)))?;

            serde_json::from_reader(BufReader::new(file))
                .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))
        }
        _ => Err(JwksGetError::InvalidSourcePath(format!(
            "unsupported scheme {} (must be either file or https)",
            url.scheme()
        ))),
    }
}

impl JwkAttestationTokenVerifier {
    pub async fn new(config: &AttestationTokenVerifierConfig) -> Result<Self> {
        let mut trusted_certs = jwk::JwkSet { keys: Vec::new() };

        for path in config.trusted_certs_paths.iter() {
            match get_jwks_from_file_or_url(path).await {
                Ok(mut jwkset) => trusted_certs.keys.append(&mut jwkset.keys),
                Err(e) => log::warn!("error getting JWKS: {:?}", e),
            }
        }

        Ok(Self { trusted_certs })
    }
}

#[async_trait]
impl AttestationTokenVerifier for JwkAttestationTokenVerifier {
    async fn verify(&self, token: String) -> Result<String> {
        if self.trusted_certs.keys.is_empty() {
            bail!("Cannot verify token since trusted JWK Set is empty");
        };

        let kid = decode_header(&token)
            .context("Failed to decode attestation token header")?
            .kid
            .ok_or(anyhow!("Failed to decode kid in the token header"))?;

        let key = &self
            .trusted_certs
            .find(&kid)
            .ok_or(anyhow!("Failed to find Jwk with kid {kid} in JwkSet"))?;

        let key_alg = key
            .common
            .key_algorithm
            .ok_or(anyhow!("Failed to find key_algorithm in Jwk"))?
            .to_string();

        let alg = Algorithm::from_str(key_alg.as_str())?;

        let dkey = DecodingKey::from_jwk(key)?;
        let token_data = decode::<Value>(&token, &dkey, &Validation::new(alg))
            .context("Failed to decode attestation token")?;

        Ok(serde_json::to_string(&token_data.claims)?)
    }
}

#[cfg(test)]
mod tests {
    use crate::token::jwk::get_jwks_from_file_or_url;
    use rstest::rstest;

    #[rstest]
    #[case("https://", true)]
    #[case("http://example.com", true)]
    #[case("file:///does/not/exist/keys.jwks", true)]
    #[case("/does/not/exist/keys.jwks", true)]
    #[tokio::test]
    async fn test_source_path_validation(#[case] source_path: &str, #[case] expect_error: bool) {
        assert_eq!(
            expect_error,
            get_jwks_from_file_or_url(source_path).await.is_err()
        )
    }

    #[rstest]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS256\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        false
    )]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"COCO42\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        true
    )]
    #[tokio::test]
    async fn test_source_reads(#[case] json: &str, #[case] expect_error: bool) {
        let tmp_dir = tempfile::tempdir().expect("to get tmpdir");
        let jwks_file = tmp_dir.path().join("test.jwks");

        let _ = std::fs::write(&jwks_file, json).expect("to get testdata written to tmpdir");

        let p = "file://".to_owned() + jwks_file.to_str().expect("to get path as str");

        assert_eq!(expect_error, get_jwks_from_file_or_url(&p).await.is_err())
    }
}
