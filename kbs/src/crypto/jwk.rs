// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jsonwebtoken::jwk::JwkSet;
use reqwest::Url;
use serde::Deserialize;
use std::fs;
use thiserror::Error;
use tracing::{debug, info};

pub(crate) const OPENID_CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";

#[derive(Error, Debug)]
pub(crate) enum JwksGetError {
    #[error("Invalid source path: {0}")]
    InvalidSourcePath(String),
    #[error("Failed to access source: {0}")]
    AccessFailed(String),
    #[error("Failed to get key material: {source}")]
    FailedToGetKeyMaterial {
        #[source]
        source: anyhow::Error,
    },
}

#[derive(Deserialize)]
pub(crate) struct OpenIDConfig {
    jwks_uri: String,
}

/// Load a JWK set from a configured source.
///
/// - `file://` and local paths: JWKS JSON file, read directly.
/// - `https://`: remote source. KBS tries to load JWKS from the configured URL directly; if
///   that fails or returns no keys, it falls back to OpenID discovery at
///   `{uri}/.well-known/openid-configuration` and loads the returned `jwks_uri`.
pub async fn read_jwk_from_uri(uri: &str) -> Result<JwkSet, JwksGetError> {
    let url = Url::parse(uri).map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;
    match url.scheme() {
        "https" => read_jwk_from_remote(&url, uri).await,
        "file" => {
            let data = fs::read(url.path())
                .map_err(|e| JwksGetError::AccessFailed(format!("open {}: {}", url.path(), e)))?;
            serde_json::from_slice(&data).map_err(|e| JwksGetError::FailedToGetKeyMaterial {
                source: Into::<anyhow::Error>::into(e).context("failed to deserialize JWK set"),
            })
        }
        _ => Err(JwksGetError::InvalidSourcePath(format!(
            "unsupported scheme {} (must be either file or https)",
            url.scheme()
        ))),
    }
}

async fn fetch_jwk_set_from_url(url: &str) -> Result<JwkSet, JwksGetError> {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?;

    let jwkset = client
        .get(url)
        .send()
        .await
        .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
        .json::<JwkSet>()
        .await
        .map_err(|e| JwksGetError::FailedToGetKeyMaterial {
            source: Into::<anyhow::Error>::into(e).context("failed to get JWK set"),
        })?;

    Ok(jwkset)
}

async fn fetch_jwk_set_via_openid_discovery(base_url: &Url) -> Result<JwkSet, JwksGetError> {
    // See https://docs.rs/url/2.5.8/url/struct.Url.html#method.join
    // A trailing slash is significant. Without it, the last path component is
    // considered to be a "file" name to be removed to get at the "directory" that is used as the base.
    let mut issuer_url = base_url.clone();
    if !issuer_url.path().ends_with('/') {
        issuer_url.set_path(&format!("{}/", issuer_url.path()));
    }
    let openid_config_url = issuer_url
        .join(OPENID_CONFIG_URL_SUFFIX)
        .map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;

    info!(
        "Getting OpenID configuration from {}",
        openid_config_url.as_str()
    );

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?;

    let oidc = client
        .get(openid_config_url.as_str())
        .send()
        .await
        .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
        .json::<OpenIDConfig>()
        .await
        .map_err(|e| JwksGetError::FailedToGetKeyMaterial {
            source: Into::<anyhow::Error>::into(e).context("failed to get OpenID configuration"),
        })?;

    fetch_jwk_set_from_url(&oidc.jwks_uri).await
}

async fn read_jwk_from_remote(base_url: &Url, uri: &str) -> Result<JwkSet, JwksGetError> {
    match fetch_jwk_set_from_url(uri).await {
        Ok(jwks) if !jwks.keys.is_empty() => {
            info!("Loaded JWK set directly from {}", uri);
            Ok(jwks)
        }
        Ok(_) => {
            debug!("empty JWK set at {uri}, trying OpenID discovery");
            fetch_jwk_set_via_openid_discovery(base_url).await
        }
        Err(e) => {
            debug!("failed to load JWK set directly from {uri}: {e}, trying OpenID discovery");
            fetch_jwk_set_via_openid_discovery(base_url).await
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::jwk::read_jwk_from_uri;
    use jsonwebtoken::jwk::KeyAlgorithm;
    use rstest::rstest;

    #[rstest]
    #[case("https://", true)]
    #[case("http://example.com", true)]
    #[case("file:///does/not/exist/keys.jwks", true)]
    #[case("/does/not/exist/keys.jwks", true)]
    #[tokio::test]
    async fn test_source_path_validation(#[case] source_path: &str, #[case] expect_error: bool) {
        assert_eq!(expect_error, read_jwk_from_uri(source_path).await.is_err())
    }

    #[rstest]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS256\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        KeyAlgorithm::HS256
    )]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"COCO42\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        KeyAlgorithm::UNKNOWN_ALGORITHM
    )]
    #[tokio::test]
    async fn test_source_reads(#[case] json: &str, #[case] alg: KeyAlgorithm) {
        let tmp_dir = tempfile::tempdir().expect("to get tmpdir");
        let jwks_file = tmp_dir.path().join("test.jwks");

        std::fs::write(&jwks_file, json).expect("to get testdata written to tmpdir");

        let p = "file://".to_owned() + jwks_file.to_str().expect("to get path as str");
        let jwtks = read_jwk_from_uri(&p).await.expect("to get jwks");
        assert_eq!(jwtks.keys.len(), 1);
        assert_eq!(jwtks.keys[0].common.key_algorithm, Some(alg));
    }
}
