// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use log::warn;

use crate::admin::error::*;
use crate::admin::AdminBackend;

#[derive(Default)]
pub struct InsecureAllowAllBackend {}

impl AdminBackend for InsecureAllowAllBackend {
    fn validate_admin_token(&self, _request: &HttpRequest) -> Result<()> {
        warn!("Allow All admin backend is set. Anyone can access admin APIs");
        Ok(())
    }
}
