// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This Error type helps to work with Actix-web

use std::fmt::{Display, Write};

use actix_web::{
    body::BoxBody,
    http::header::{self, TryIntoHeaderValue},
    web::BytesMut,
    HttpResponse, Responder, ResponseError,
};
use kbs_types::ErrorInformation;
use serde::Serialize;
use strum_macros::AsRefStr;
use thiserror::Error;

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors";

pub type Result<T> = std::result::Result<T, Error>;

#[allow(dead_code)]
#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Attestation claims get failed: {0}")]
    AttestationClaimsGetFailed(String),

    #[error("Received illegal attestation claims: {0}")]
    AttestationClaimsParseFailed(String),

    #[error("The cookie is expired")]
    ExpiredCookie,

    #[error("Authentication failed: {0}")]
    FailedAuthentication(String),

    #[error("The cookie is invalid")]
    InvalidCookie,

    #[error("The request is invalid: {0}")]
    InvalidRequest(String),

    #[error("Json Web Encryption failed: {0}")]
    JWEFailed(String),

    #[error("The cookie is missing")]
    MissingCookie,

    #[error("Policy error: {0}")]
    PolicyEndpoint(String),

    #[error("Resource policy engine evaluate failed: {0}")]
    PolicyEngineFailed(String),

    #[error("Public key get failed: {0}")]
    PublicKeyGetFailed(String),

    #[error("Read secret failed: {0}")]
    ReadSecretFailed(String),

    #[error("Set secret failed: {0}")]
    SetSecretFailed(String),

    #[error("Attestation token issue failed: {0}")]
    TokenIssueFailed(String),

    #[error("Received an illegal token: {0}")]
    TokenParseFailed(String),

    #[error("The cookie is unauthenticated")]
    UnAuthenticatedCookie,

    #[error("User public key not provided when launching the KBS")]
    UserPublicKeyNotProvided,
}

/// For example, if we want to raise an error of `MissingCookie`
/// ```no-run
/// raise_error!(Error::MissingCookie);
/// ```
/// is short for
/// ```no-run
/// return Err(Error::MissingCookie);
/// ```
#[macro_export]
macro_rules! raise_error {
    ($error: expr) => {
        return Err($error)
    };
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut detail = String::new();

        // The write macro here will only raise error when OOM of the string.
        write!(&mut detail, "{}", self).expect("written error response failed");
        let info = ErrorInformation {
            error_type: format!("{ERROR_TYPE_PREFIX}/{}", self.as_ref()),
            detail,
        };

        // All the fields inside the ErrorInfo are printable characters, so this
        // error cannot happen.
        // A test covering all the possible error types are given to ensure this.
        let body = serde_json::to_string(&info).expect("serialize error response failed");

        // Due to the definition of KBS attestation protocol, we set the http code.
        let mut res = match self {
            Error::ReadSecretFailed(_) => HttpResponse::NotFound(),
            _ => HttpResponse::Unauthorized(),
        };

        res.body(BoxBody::new(body))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use crate::http::Error;

    #[rstest]
    #[case(Error::AttestationFailed("test".into()))]
    #[case(Error::ExpiredCookie)]
    #[case(Error::FailedAuthentication("test".into()))]
    #[case(Error::InvalidCookie)]
    #[case(Error::ExpiredCookie)]
    #[case(Error::MissingCookie)]
    #[case(Error::InvalidRequest("test".into()))]
    #[case(Error::JWEFailed("test".into()))]
    #[case(Error::PolicyEndpoint("test".into()))]
    #[case(Error::PublicKeyGetFailed("test".into()))]
    #[case(Error::ReadSecretFailed("test".into()))]
    #[case(Error::SetSecretFailed("test".into()))]
    #[case(Error::TokenIssueFailed("test".into()))]
    #[case(Error::TokenParseFailed("test".into()))]
    #[case(Error::UnAuthenticatedCookie)]
    #[case(Error::UserPublicKeyNotProvided)]
    fn into_error_response(#[case] err: Error) {
        let _ = actix_web::ResponseError::error_response(&err);
    }
}
