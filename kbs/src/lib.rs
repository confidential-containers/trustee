// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS API server

#[cfg(feature = "as")]
pub mod attestation;

/// KBS config
pub mod config;
pub use config::KbsConfig;
mod token;

/// Resource Policy Engine
pub mod policy_engine;

pub mod api_server;
pub use api_server::ApiServer;

pub mod error;
pub mod plugins;
pub use error::*;

pub mod admin;
pub mod http;
pub mod jwe;
