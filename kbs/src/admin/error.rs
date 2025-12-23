// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use strum::AsRefStr;
use thiserror::Error;
use tracing::error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Admin access denied: {reason}")]
    AdminAccessDenied { reason: String },

    #[error("Failed to parse admin public key")]
    ParsePublicKey(#[from] jsonwebtoken::errors::Error),

    #[error("Failed to parse HTTP Auth Bearer header")]
    ParseAuthHeaderFailed(#[from] actix_web::error::ParseError),

    #[error("Read admin public key failed")]
    ReadPublicKey(#[from] std::io::Error),

    #[error("Admin Role regex must be anchored.")]
    UnanchoredRegex,

    #[error("Failed to parse regex: {0}")]
    ParseRegex(#[from] regex::Error),

    #[error("Failed to parse JWK/JWKS file")]
    ParseJwk(#[from] serde_json::Error),

    #[error("Invalid admin token verifier config: {0}")]
    InvalidTokenVerifierConfig(String),

    #[error("Read verification materials failed: {source}")]
    ReadVerificationMaterialsFailed {
        #[source]
        source: anyhow::Error,
    },
}
