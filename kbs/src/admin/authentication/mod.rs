// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::HttpRequest;
use serde::Deserialize;

use crate::admin::{
    authentication::bearer_jwt::{BearerJwtConfig, BearerJwtTokenVerifier},
    error::Result,
    Claims,
};

pub mod bearer_jwt;

/// TokenVerifier parses the token from the request and returns the claims.
pub trait TokenVerifierTrait: Send + Sync {
    fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims>;
}

#[derive(Clone)]
pub struct TokenVerifier {
    verifier: Arc<dyn TokenVerifierTrait>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationType {
    BearerJwt(BearerJwtConfig),
}

impl TokenVerifier {
    pub async fn new(value: AuthenticationType) -> Result<Self> {
        match value {
            AuthenticationType::BearerJwt(config) => Ok(TokenVerifier {
                verifier: Arc::new(BearerJwtTokenVerifier::new(config).await?),
            }),
        }
    }

    pub fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims> {
        self.verifier.parse_and_verify(request)
    }
}
