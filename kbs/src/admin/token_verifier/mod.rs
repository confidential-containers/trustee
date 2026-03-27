// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use actix_web::HttpRequest;
use serde::Deserialize;

use crate::admin::{
    error::Result,
    token_verifier::bearer_jwt::{BearerJwtConfig, BearerJwtTokenVerifier},
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
#[serde(tag = "type")]
pub enum TokenVerifierType {
    BearerJwt(BearerJwtConfig),
}

impl TokenVerifier {
    pub async fn new(value: TokenVerifierType) -> Result<Self> {
        match value {
            TokenVerifierType::BearerJwt(config) => Ok(TokenVerifier {
                verifier: Arc::new(BearerJwtTokenVerifier::new(config).await?),
            }),
        }
    }

    pub fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims> {
        self.verifier.parse_and_verify(request)
    }
}
