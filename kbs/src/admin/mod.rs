// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use log::{info, warn};
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

pub mod allow_all;
pub mod deny_all;
pub mod simple;

pub mod error;
pub use error::*;

use allow_all::InsecureAllowAllBackend;
use deny_all::DenyAllBackend;
use simple::{SimpleAdminBackend, SimpleAdminConfig};

#[derive(Clone)]
pub(crate) struct Admin {
    backend: Arc<dyn AdminBackend>,
    roles: HashMap<String, Regex>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AdminBackendType {
    Simple(SimpleAdminConfig),
    InsecureAllowAll,
    DenyAll,
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
    /// Admin roles control which admin personas can access
    /// which endpoints.
    ///
    /// If no admin roles are specified, all admin will be able
    /// to access all endpoints.
    pub roles: Vec<AdminRole>,
}

/// An admin role is a rule that grants access for some roles to some endpoints.
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminRole {
    /// The admin role that this rule applies to.
    /// The id is case insensitive.
    pub id: String,
    /// A regular expression selecting request paths this rule allows.
    /// In other words, the paths that the above role can access.
    #[serde(default)]
    pub allowed_endpoints: String,
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
        };

        // Parse roles to ensure valid regexes and no duplicates.
        let mut roles = HashMap::new();
        for role in value.roles {
            if !role.allowed_endpoints.starts_with("^/kbs")
                || !role.allowed_endpoints.ends_with("$")
            {
                return Err(Error::UnanchoredRegex);
            }

            let re = Regex::new(&role.allowed_endpoints)?;

            if roles.insert(role.id, re).is_some() {
                return Err(Error::DuplicateAdminRole);
            }
        }

        Ok(Admin { backend, roles })
    }
}

impl Admin {
    pub fn check_admin_access(&self, request: &HttpRequest) -> Result<()> {
        let Ok(role) = self.backend.validate_admin_token(request) else {
            info!("Failed to validate admin token.");
            return Err(Error::AdminAccessDenied);
        };

        info!("Admin Role: {role}");

        // If there are no roles specified, allow all.
        if self.roles.is_empty() {
            info!(
                "No admin roles configured. Allowing Request to {}",
                request.uri()
            );
            return Ok(());
        }

        // If at least one role is specified, the request must be explicitly allowed.
        if let Some(re) = self.roles.get(&role) {
            if re.is_match(&request.uri().to_string()) {
                info!("Allowing Request to {}", request.uri());
                return Ok(());
            }
        }

        info!("Not allowing Admin access to {}", request.uri());
        Err(Error::AdminAccessDenied)
    }
}

/// Admin backends determine whether a user should be granted access
/// to admin endpoints.
pub(crate) trait AdminBackend: Send + Sync {
    /// When a request is made to an admin endpoint, this method should be called
    /// to validate that the user making the request is authorized
    /// to access admin functionality.
    ///
    /// If the token is valid, the backend will return an admin role.
    fn validate_admin_token(&self, request: &HttpRequest) -> Result<String>;
}

#[cfg(test)]
mod tests {

    use super::*;
    use serde_json::json;

    #[test]
    pub fn make_admin_object() {
        // basic (backwards compatible)
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
        });

        let config: AdminConfig = serde_json::from_value(admin_config_json).unwrap();
        let _admin = Admin::try_from(config).unwrap();

        // with invalid role (wrong field name)
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
            "roles" : [{
                "id": "Anonymous",
                "allowed_paths": "^/kbs/xyz$"
            }]
        });

        let config = serde_json::from_value::<AdminConfig>(admin_config_json);
        assert!(config.is_err());

        // with invalid role (bad regex)
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
            "roles" : [{
                "id": "Anonymous",
                "allowed_endpoints": "^/kbs/(xyz$"
            }]
        });

        let config: AdminConfig = serde_json::from_value(admin_config_json).unwrap();
        let admin = Admin::try_from(config);
        assert!(admin.is_err());

        // with invalid role (duplicate role)
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
            "roles" : [{
                "id": "Anonymous",
                "allowed_endpoints": "^/kbs/xyz$"
            },
            {
                "id": "Anonymous",
                "allowed_endpoints": "^/kbs/abc$"
            }]
        });

        let config: AdminConfig = serde_json::from_value(admin_config_json).unwrap();
        let admin = Admin::try_from(config);
        assert!(admin.is_err());

        // with invalid role (unanchored regex)
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
            "roles" : [{
                "id": "Anonymous",
                "allowed_endpoints": "xyz"
            }]
        });

        let config: AdminConfig = serde_json::from_value(admin_config_json).unwrap();
        let admin = Admin::try_from(config);
        assert!(admin.is_err());
    }

    #[test]
    pub fn check_requests() {
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
            "roles" : [{
                "id": "Anonymous",
                "allowed_endpoints": "^/kbs/v0/resource/a/.+/c$"
            }]
        });

        let config: AdminConfig = serde_json::from_value(admin_config_json).unwrap();
        let admin = Admin::try_from(config).unwrap();

        // valid request
        let req = actix_web::test::TestRequest::post()
            .uri("/kbs/v0/resource/a/b/c")
            .to_http_request();
        admin.check_admin_access(&req).unwrap();

        // invalid request
        let req = actix_web::test::TestRequest::post()
            .uri("/kbs/v0/resource/b/b/c")
            .to_http_request();
        assert!(admin.check_admin_access(&req).is_err());
    }

    #[test]
    pub fn check_requests_wrong_role() {
        let admin_config_json = json!({
            "type": "InsecureAllowAll",
            "roles" : [{
                "id": "Steve",
                "allowed_endpoints": "^/kbs/v0/resource/a/.+/c$"
            }]
        });

        let config: AdminConfig = serde_json::from_value(admin_config_json).unwrap();
        let admin = Admin::try_from(config).unwrap();

        let req = actix_web::test::TestRequest::post()
            .uri("/kbs/v0/resource/a/b/c")
            .to_http_request();
        assert!(admin.check_admin_access(&req).is_err());
    }
}
