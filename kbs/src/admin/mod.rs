// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use log::{info, warn};
use serde::Deserialize;
use serde_json::{json, Value};
use std::sync::Arc;

pub mod allow_all;
pub mod deny_all;
pub mod password;
pub mod simple;

pub mod error;
pub use error::*;

use allow_all::InsecureAllowAllBackend;
use deny_all::DenyAllBackend;
use password::{PasswordAdminBackend, PasswordAdminConfig};
use simple::{SimpleAdminBackend, SimpleAdminConfig};

#[derive(Clone)]
pub(crate) struct Admin {
    backend: Arc<dyn AdminBackend>,
}

// create a simple backend
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AdminBackendType {
    Simple(SimpleAdminConfig),
    InsecureAllowAll,
    DenyAll,
    Password(PasswordAdminConfig),
}

impl Default for AdminBackendType {
    fn default() -> Self {
        AdminBackendType::Simple(SimpleAdminConfig {
            personas: Vec::new(),
        })
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct AdminConfig {
    #[serde(flatten)]
    pub admin_backend: AdminBackendType,
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
            AdminBackendType::DenyAll => Arc::new(DenyAllBackend::default()) as _,
            AdminBackendType::Password(config) => Arc::new(PasswordAdminBackend::new(config)?) as _,
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

    pub fn generate_admin_token(&self, login_data: &[u8]) -> Result<String> {
        let login_data: Value = serde_json::from_slice(login_data)?;

        let token = self.backend.generate_admin_token(login_data)?;
        let response = json!({ "admin_token": token });

        Ok(response.to_string())
    }
}

/// Admin backends determine whether a user should be granted access
/// to admin endpoints.
pub(crate) trait AdminBackend: Send + Sync {
    /// When a request is made to an admin endpoint, this method should be called
    /// to validate that the user making the request is authorized
    /// to access admin functionality.
    fn validate_admin_token(&self, request: &HttpRequest) -> Result<()>;

    /// This method allows a potential admin to request an admin token
    /// given some login information (such as a username and password).
    /// If the login information is valid, an admin token will be returned.
    fn generate_admin_token(&self, _login_data: serde_json::Value) -> Result<String> {
        Err(Error::NoAdminLogin)
    }
}
