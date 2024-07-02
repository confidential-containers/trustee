// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "as")]
use crate::attestation::{AttestationService, AS_TOKEN_TEE_PUBKEY_PATH};
use crate::auth::validate_auth;
#[cfg(feature = "policy")]
use crate::policy_engine::PolicyEngine;
#[cfg(feature = "resource")]
use crate::resource::{set_secret_resource, Repository, ResourceDesc};
#[cfg(feature = "as")]
use crate::session::{SessionMap, KBS_SESSION_ID};
#[cfg(feature = "resource")]
use crate::token::AttestationTokenVerifier;
use actix_web::Responder;
use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use jwt_simple::prelude::Ed25519PublicKey;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

#[cfg(feature = "as")]
mod attest;

mod config;
mod error;

#[cfg(feature = "resource")]
mod resource;

#[cfg(feature = "as")]
/// RESTful APIs that related to attestation
pub use attest::*;

/// RESTful APIs that configure KBS and AS, require user authentication
pub use self::config::*;

#[cfg(feature = "resource")]
/// RESTful APIs that to get secret resources, need attestation verification
pub use resource::*;

pub use error::*;
