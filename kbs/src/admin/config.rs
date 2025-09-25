// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use serde::Deserialize;

pub const DEFAULT_INSECURE_API: bool = false;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct AdminConfig {
    /// Public key used to authenticate the resource registration endpoint token (JWT).
    /// Only JWTs signed with the corresponding private keys are authenticated.
    pub auth_public_key: Option<PathBuf>,

    /// Insecure HTTP APIs.
    /// WARNING: Using this option enables KBS insecure APIs such as Resource Registration without
    /// verifying the JWK.
    pub insecure_api: bool,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            auth_public_key: None,
            insecure_api: DEFAULT_INSECURE_API,
        }
    }
}
