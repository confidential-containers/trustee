// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use log::{info, warn};
use serde::Deserialize;
use std::sync::Arc;

pub mod allow_all;
pub mod error;
pub mod simple;
pub use error::*;

use allow_all::InsecureAllowAllBackend;
use simple::{SimpleAdminBackend, SimpleAdminConfig};

#[derive(Clone)]
pub(crate) struct Admin {
    backend: Arc<dyn AdminBackend>,
}

// create a simple backend
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AdminBackendType {
    Simple(SimpleAdminConfig),
    #[default]
    InsecureAllowAll,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct AdminConfig {
    #[serde(flatten)]
    pub admin_backend: AdminBackendType,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            admin_backend: AdminBackendType::Simple(SimpleAdminConfig {
                personas: Vec::new(),
            }),
        }
    }
}

impl TryFrom<AdminConfig> for Admin {
    type Error = Error;
    fn try_from(value: AdminConfig) -> Result<Self> {
        let backend = match value.admin_backend {
            AdminBackendType::InsecureAllowAll => {
                warn!("The Allow All admin backend is being used. Admin endpoints will be accessible to anyone.");
                Arc::new(InsecureAllowAllBackend::default()) as _
            }
            AdminBackendType::Simple(config) => Arc::new(SimpleAdminBackend::new(config)?) as _,
        };

        Ok(Admin { backend })
    }
}

impl Admin {
    pub fn validate_admin_token(&self, request: &HttpRequest) -> Result<()> {
        let res = self.backend.validate_admin_token(request);
        match res {
            Ok(()) => info!("Allowing Admin access for {}", request.full_url().as_str()),
            Err(ref e) => info!(
                "Not allowing Admin access for {} due to: \n{}",
                request.full_url().as_str(),
                e
            ),
        }

        res
    }
}

/// Admin backends determine whether a user should be granted access
/// to admin endpoints.
pub(crate) trait AdminBackend: Send + Sync {
    /// When a request is made to an admin endpoint, this method should be called
    /// to validate that the user making the request is authorized
    /// to access admin functionality.
    fn validate_admin_token(&self, request: &HttpRequest) -> Result<()>;
}
