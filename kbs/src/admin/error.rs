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

    #[error("The admin token is missing required information.")]
    AdminTokenInvalid,

    #[error("An invalid hash was used.")]
    InvalidHash,

    #[error("Backend does not support admin login interface.")]
    NoAdminLogin,

    #[error("`auth_public_key` is not set in the config file")]
    NoPublicKeyGiven,

    #[error("Failed to parse admin public key")]
    ParsePublicKey(#[from] jwt_simple::Error),

    #[error("Failed to parse HTTP Auth Bearer header")]
    ParseAuthHeaderFailed(#[from] actix_web::error::ParseError),

    #[error("Failed to parse admin login request JSON")]
    ParseAdminLoginJsonFailed(#[from] serde_json::Error),

    #[error("Failed to parse admin login request")]
    ParseAdminLoginFailed,

    #[error("Read admin public key failed")]
    ReadPublicKey(#[from] std::io::Error),

    #[error("Failed to generate admin token.")]
    TokenCreationFailed,

    #[error("Admin token has expired. You may need to login again.")]
    TokenExpired,

    #[error("Username or password incorrect.")]
    WrongUsernameOrPassword,
}
