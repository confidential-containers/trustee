// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use tracing::warn;

use crate::admin::error::*;
use crate::admin::AdminBackend;

#[derive(Default)]
pub struct DenyAllBackend {}

impl AdminBackend for DenyAllBackend {
    fn validate_admin_token(&self, _request: &HttpRequest) -> Result<String> {
        warn!("Admin endpoints are disabled");
        Err(Error::AdminEndpointsDisabled)
    }
}
