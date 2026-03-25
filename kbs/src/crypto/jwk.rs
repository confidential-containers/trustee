// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use jsonwebtoken::jwk::JwkSet;
use reqwest::{get, Url};
use serde::Deserialize;
use std::fs;
use thiserror::Error;
use tracing::info;

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

pub async fn read_jwk_from_uri(
    uri: &str,
    insecure_public_key_from_uri: bool,
) -> Result<JwkSet, JwksGetError> {
    let url = Url::parse(uri).map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;
    match url.scheme() {
        "https" | "http" if insecure_public_key_from_uri => {
            let openid_config_url = url
                .join(OPENID_CONFIG_URL_SUFFIX)
                .map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;

            info!(
                "Getting OpenID configuration from {}",
                openid_config_url.as_str()
            );
            let oidc = get(openid_config_url.as_str())
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                .json::<OpenIDConfig>()
                .await
                .map_err(|e| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(e)
                        .context("failed to get OpenID configuration"),
                })?;

            get(oidc.jwks_uri)
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                .json::<JwkSet>()
                .await
                .map_err(|e| JwksGetError::FailedToGetKeyMaterial {
                    source: Into::<anyhow::Error>::into(e).context("failed to get JWK set"),
                })
        }
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
