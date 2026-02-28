// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This Error type helps to work with Actix-web

use std::fmt::Write;

use actix_web::{body::BoxBody, HttpResponse, ResponseError};
use kbs_types::ErrorInformation;
use log::error;
use strum::AsRefStr;
use thiserror::Error;

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors";

pub type Result<T> = std::result::Result<T, Error>;

/// Carries an HTTP status code through the anyhow error chain for external plugin errors.
/// Produced by `GrpcPluginProxy` and downcast in `api_server.rs`.
#[derive(Debug)]
pub struct PluginCallError {
    pub http_status: u16,
    pub message: String,
}

impl std::fmt::Display for PluginCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Plugin error (HTTP {}): {}",
            self.http_status, self.message
        )
    }
}

impl std::error::Error for PluginCallError {}

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Admin auth error: {0}")]
    AdminAuth(#[from] crate::admin::Error),

    #[cfg(feature = "as")]
    #[error("Attestation error: {0}")]
    AttestationError(#[from] crate::attestation::Error),

    #[error("HTTP initialization failed")]
    HTTPFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("HTTPS initialization failed")]
    HTTPSFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Request path {path} is invalid")]
    InvalidRequestPath { path: String },

    #[error("JWE failed")]
    JweError {
        #[source]
        source: anyhow::Error,
    },

    #[error("PluginManager initialization failed")]
    PluginManagerInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Plugin {plugin_name} not found")]
    PluginNotFound { plugin_name: String },

    #[error("Plugin internal error")]
    PluginInternalError {
        #[source]
        source: anyhow::Error,
    },

    #[error("Plugin error (HTTP {http_status}): {message}")]
    PluginError { http_status: u16, message: String },

    #[error("Access denied by policy")]
    PolicyDeny,

    #[error("Policy engine error")]
    PolicyEngine(#[from] crate::policy_engine::KbsPolicyEngineError),

    #[error("RVPS configuration failed: {message}")]
    RvpsError { message: String },

    #[error("Serialize/Deserialize failed")]
    SerdeError(#[from] serde_json::Error),

    #[error("Attestation Token not found")]
    TokenNotFound,

    #[error("Token Verifier error")]
    TokenVerifierError(#[from] crate::token::Error),

    #[error("Prometheus error")]
    PrometheusError {
        #[from]
        source: prometheus::Error,
    },
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let mut detail = String::new();

        // The write macro here will only raise error when OOM of the string.
        write!(&mut detail, "{}", self).expect("Failed to write error");
        let info = ErrorInformation {
            error_type: format!("{ERROR_TYPE_PREFIX}/{}", self.as_ref()),
            detail,
        };

        // All the fields inside the ErrorInfo are printable characters, so this
        // error cannot happen.
        // A test covering all the possible error types are given to ensure this.
        let body = serde_json::to_string(&info).expect("Failed to serialize error");

        // Per the KBS protocol, errors should yield 401 or 404 reponses
        let mut res = match self {
            Error::InvalidRequestPath { .. } | Error::PluginNotFound { .. } => {
                HttpResponse::NotFound()
            }
            Error::PluginError { http_status, .. } => match http_status {
                400 => HttpResponse::BadRequest(),
                401 => HttpResponse::Unauthorized(),
                403 => HttpResponse::Forbidden(),
                404 => HttpResponse::NotFound(),
                405 => HttpResponse::MethodNotAllowed(),
                500 => HttpResponse::InternalServerError(),
                503 => HttpResponse::ServiceUnavailable(),
                _ => HttpResponse::InternalServerError(),
            },
            _ => HttpResponse::Unauthorized(),
        };

        error!("{self:?}");

        res.body(BoxBody::new(body))
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::Error;

    #[rstest]
    #[case(Error::InvalidRequestPath{path: "test".into()})]
    #[case(Error::PluginNotFound{plugin_name: "test".into()})]
    #[case(Error::PluginError{http_status: 404, message: "test".into()})]
    fn into_error_response(#[case] err: Error) {
        let _ = actix_web::ResponseError::error_response(&err);
    }
}
