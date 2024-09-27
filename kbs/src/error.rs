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

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Admin auth error")]
    AdminAuth(#[from] crate::admin::Error),

    #[cfg(feature = "as")]
    #[error("Attestation error")]
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

    #[error("Accessed path {path} is illegal")]
    IllegalAccessedPath { path: String },

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

    #[error("Access denied by policy")]
    PolicyDeny,

    #[error("Policy engine error")]
    PolicyEngine(#[from] crate::policy_engine::KbsPolicyEngineError),

    #[cfg(feature = "resource")]
    #[error("Resource access failed")]
    ResourceAccessFailed(#[from] crate::resource::Error),

    #[error("Serialize/Deserialize failed")]
    SerdeError(#[from] serde_json::Error),

    #[error("Attestation Token not found")]
    TokenNotFound,

    #[error("Token Verifier error")]
    TokenVerifierError(#[from] crate::token::Error),
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
            Error::IllegalAccessedPath { .. } | Error::PluginNotFound { .. } => {
                HttpResponse::NotFound()
            }
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
    #[case(Error::IllegalAccessedPath{path: "test".into()})]
    #[case(Error::PluginNotFound{plugin_name: "test".into()})]
    fn into_error_response(#[case] err: Error) {
        let _ = actix_web::ResponseError::error_response(&err);
    }
}
