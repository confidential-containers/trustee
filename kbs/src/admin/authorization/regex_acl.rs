// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use actix_web::HttpRequest;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::admin::{authorization::AuthorizationTrait, error::*, AuthorizationDecision, Claims};

/// An admin role is a rule that grants access for some roles to some endpoints.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminRole {
    /// The admin role that this rule applies to.
    /// The subject is case insensitive.
    pub subject: String,
    /// A regular expression selecting request paths this rule allows.
    /// In other words, the paths that the above role can access.
    #[serde(default)]
    pub allowed_endpoints: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegexAclConfig {
    // TODO: replace this with a file
    #[serde(default)]
    roles: Vec<AdminRole>,
}

pub struct RegexAclAuthorizer {
    roles: HashMap<String, Regex>,
}

impl TryFrom<RegexAclConfig> for RegexAclAuthorizer {
    type Error = Error;
    fn try_from(config: RegexAclConfig) -> Result<Self> {
        let mut roles = HashMap::new();
        for role in config.roles {
            if !role.allowed_endpoints.starts_with("^/kbs")
                || !role.allowed_endpoints.ends_with("$")
            {
                return Err(Error::UnanchoredRegex);
            }
            let regex = Regex::new(&role.allowed_endpoints)?;
            if roles.insert(role.subject, regex).is_some() {
                return Err(Error::DuplicateAdminRole);
            }
        }
        Ok(RegexAclAuthorizer { roles })
    }
}

impl AuthorizationTrait for RegexAclAuthorizer {
    fn authorize(&self, claims: Claims, request: &HttpRequest) -> Result<AuthorizationDecision> {
        let role = claims.subject;
        let Some(regex) = self.roles.get(&role) else {
            return Err(Error::AdminAccessDenied {
                reason: "Role not found".to_string(),
            });
        };

        if regex.is_match(&request.uri().to_string()) {
            return Ok(AuthorizationDecision {
                allowed: true,
                reason: "Role allowed".to_string(),
            });
        }
        Err(Error::AdminAccessDenied {
            reason: "Role not allowed".to_string(),
        })
    }
}
