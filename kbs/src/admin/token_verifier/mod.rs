// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use actix_web::HttpRequest;
use serde::Deserialize;

use crate::admin::{
    error::{Error, Result},
    token_verifier::bearer_jwt::{BearerJwtConfig, BearerJwtTokenVerifier},
    Claims,
};

pub mod bearer_jwt;

/// TokenVerifier parses the token from the request and returns the claims.
pub trait TokenVerifierTrait: Send + Sync {
    fn parse_and_verify(&self, request: &HttpRequest) -> Result<Claims>;
}

pub type TokenVerifier = Arc<dyn TokenVerifierTrait>;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum TokenVerifierType {
    BearerJwt(BearerJwtConfig),
}

impl TryFrom<TokenVerifierType> for TokenVerifier {
    type Error = Error;
    fn try_from(value: TokenVerifierType) -> Result<Self> {
        match value {
            TokenVerifierType::BearerJwt(config) => {
                Ok(Arc::new(BearerJwtTokenVerifier::new(config)?))
            }
        }
    }
}
