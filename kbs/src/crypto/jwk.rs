// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jsonwebtoken::jwk::JwkSet;
use reqwest::{get, Url};
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
/// - `https://`: remote source. KBS tries to load JWKS from the configured URL directly; if that
///   fails or returns no keys, it falls back to OpenID discovery at
///   `{uri}/.well-known/openid-configuration` and loads the returned `jwks_uri`.
pub async fn read_jwk_from_uri(uri: &str) -> Result<JwkSet, JwksGetError> {
    let url = Url::parse(uri).map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;
    match url.scheme() {
        "file" => {
            let data = fs::read(url.path())
                .map_err(|e| JwksGetError::AccessFailed(format!("open {}: {}", url.path(), e)))?;
            serde_json::from_slice(&data).map_err(|e| JwksGetError::FailedToGetKeyMaterial {
                source: Into::<anyhow::Error>::into(e).context("failed to deserialize JWK set"),
            })
        }
        "https" => {
            // Try to load a JWK set directly from the configured URL first.
            match get(uri)
                .await
                .map_err(|source| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(source).context("failed to get JWK set"),
                })?
                .json::<JwkSet>()
                .await
                .map_err(|source| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(source)
                        .context("failed to deserialize into JWK set"),
                }) {
                Ok(jwks) if !jwks.keys.is_empty() => return Ok(jwks),
                Ok(_) => debug!("empty JWK set at {uri}, trying OpenID discovery"),
                Err(e) => debug!(
                    "failed to load JWK set directly from {uri}: {e}, trying OpenID discovery"
                ),
            }

            // Fall back to OpenID discovery at `{uri}/.well-known/openid-configuration`.
            let openid_config_url = build_openid_config_url(&url)?;
            info!("Getting OpenID configuration from {openid_config_url}");
            let oidc: OpenIDConfig = get(openid_config_url.as_str())
                .await
                .map_err(|source| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(source)
                        .context("failed to get OpenID configuration"),
                })?
                .json::<OpenIDConfig>()
                .await
                .map_err(|source| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(source)
                        .context("failed to deserialize into OpenID configuration"),
                })?;

            let jwks_url = Url::parse(&oidc.jwks_uri).map_err(|e| {
                JwksGetError::InvalidSourcePath(format!("invalid jwks_uri {}: {e}", oidc.jwks_uri))
            })?;

            let jwks = get(jwks_url.as_str())
                .await
                .map_err(|source| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(source).context("failed to get JWK set"),
                })?
                .json::<JwkSet>()
                .await
                .map_err(|source| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(source)
                        .context("failed to deserialize into JWK set"),
                })?;

            Ok(jwks)
        }
        scheme => Err(JwksGetError::InvalidSourcePath(format!(
            "unsupported scheme {scheme} (must be either file or https)"
        ))),
    }
}

/// Build the OpenID configuration discovery URL (`{base}/.well-known/openid-configuration`).
///
/// A trailing slash on the base path is significant for [`Url::join`]: without it the last path
/// segment is treated as a file name and dropped (so `https://host/realms/foo` would lose `foo`),
/// hence we ensure one is present first.
fn build_openid_config_url(base: &Url) -> Result<Url, JwksGetError> {
    let mut issuer_url = base.clone();
    if !issuer_url.path().ends_with('/') {
        issuer_url.set_path(&format!("{}/", issuer_url.path()));
    }
    issuer_url
        .join(OPENID_CONFIG_URL_SUFFIX)
        .map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{build_openid_config_url, read_jwk_from_uri};
    use jsonwebtoken::jwk::KeyAlgorithm;
    use reqwest::Url;
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

    /// `Url::join` drops the last path segment unless the base ends with `/`, so verify the
    /// discovery URL is built correctly for issuer bases with and without a trailing slash.
    #[rstest]
    #[case(
        "https://host/realms/foo",
        "https://host/realms/foo/.well-known/openid-configuration"
    )]
    #[case(
        "https://host/realms/foo/",
        "https://host/realms/foo/.well-known/openid-configuration"
    )]
    #[case("https://host", "https://host/.well-known/openid-configuration")]
    #[case("https://host/", "https://host/.well-known/openid-configuration")]
    fn test_build_openid_config_url(#[case] base: &str, #[case] expected: &str) {
        let url = Url::parse(base).expect("valid base url");
        let got = build_openid_config_url(&url).expect("build discovery url");
        assert_eq!(got.as_str(), expected);
    }
}
