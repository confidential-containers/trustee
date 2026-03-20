// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use actix_web::HttpRequest;
use serde::{Deserialize, Serialize};

use crate::admin::{
    authorization::regex_acl::{RegexAclAuthorizer, RegexAclConfig},
    error::*,
    AuthorizationDecision, Claims,
};

pub mod regex_acl;

/// Authorization checks if the claims have access to the given path.
pub trait AuthorizationTrait: Send + Sync {
    fn authorize(&self, claims: Claims, request: &HttpRequest) -> Result<AuthorizationDecision>;
}

pub type Authorization = Arc<dyn AuthorizationTrait>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AuthorizerType {
    RegexAcl(RegexAclConfig),
}

impl TryFrom<AuthorizerType> for Authorization {
    type Error = Error;
    fn try_from(value: AuthorizerType) -> Result<Self> {
        match value {
            AuthorizerType::RegexAcl(config) => Ok(Arc::new(RegexAclAuthorizer::try_from(config)?)),
        }
    }
}
