// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::Responder;
use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use jwt_simple::prelude::Ed25519PublicKey;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request};
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::{Mutex, RwLock};

use crate::attestation::AttestationService;
use crate::auth::validate_auth;
use crate::resource::{set_secret_resource, Repository, ResourceDesc};
use crate::session::{Session, SessionMap, KBS_SESSION_ID};
use crate::token::AttestationTokenVerifier;

mod attest;
mod config;
mod error;
mod resource;

/// RESTful APIs that related to attestation
pub use attest::*;

/// RESTful APIs that configure KBS and AS, require user authentication
pub use config::*;

/// RESTful APIs that to get secret resources, need attestation verification
pub use resource::*;

pub use error::*;
