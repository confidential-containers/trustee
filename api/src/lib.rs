// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! RESTful APIs

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use jwt_simple::prelude::Ed25519PublicKey;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request};
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::{Mutex, RwLock};

use ::resource::{set_secret_resource, Repository, ResourceDesc};
use attestation::AttestationService;
use internal::auth::validate_auth;
use session::{Session, SessionMap, KBS_SESSION_ID};
use token::AttestationTokenBroker;

mod attest;
mod config;
mod public;
mod resource;

/// RESTful APIs that related to attestation
pub use attest::*;

/// RESTful APIs that configure KBS and AS, require user authentication
pub use config::*;

/// RESTful APIs that is public
pub use public::*;

/// RESTful APIs that to get secret resources, need attestation verification
pub use crate::resource::*;

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors/";

#[allow(missing_docs)]
#[derive(Debug, EnumString)]
pub enum ErrorInformationType {
    ExpiredCookie,
    FailedAuthentication,
    InvalidCookie,
    MissingCookie,
    UnAuthenticatedCookie,
    VerificationFailed,
    JWTVerificationFailed,
}

#[allow(missing_docs)]
pub fn error_info(error_type: ErrorInformationType, detail: &str) -> ErrorInformation {
    ErrorInformation {
        error_type: format!("{ERROR_TYPE_PREFIX}{error_type:?}"),
        detail: detail.to_string(),
    }
}
