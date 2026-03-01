// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Admin Token could not be verified for any admin persona")]
    AdminAccessDenied,

    #[error("Admin endpoints disabled.")]
    AdminEndpointsDisabled,

    #[error("Duplicate Admin Role")]
    DuplicateAdminRole,

    #[error("Invalid Regular Expression in Role")]
    InvalidRoleRegex(#[from] regex::Error),

    #[error("`auth_public_key` is not set in the config file")]
    NoPublicKeyGiven,

    #[error("Failed to parse admin public key")]
    ParsePublicKey(#[from] jsonwebtoken::errors::Error),

    #[error("Failed to parse HTTP Auth Bearer header")]
    ParseAuthHeaderFailed(#[from] actix_web::error::ParseError),

    #[error("Read admin public key failed")]
    ReadPublicKey(#[from] std::io::Error),

    #[error("Admin Role regex must be anchored.")]
    UnanchoredRegex,
}
