// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::admin::{authorization::AuthorizationTrait, error::*, AuthorizationDecision, Claims};

/// An ACL rule that grants a specific role access to selected endpoints.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminAclRule {
    /// The admin role that this rule applies to.
    pub role: String,

    /// A regular expression selecting request paths this rule allows.
    #[serde(default)]
    pub allowed_endpoints: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RegexAclConfig {
    #[serde(default)]
    acls: Vec<AdminAclRule>,
}

/// The inner expression of an admin ACL rule inside [`RegexAclAuthorizer`]
struct AdminAclRuleEntry {
    regex: Regex,
    role: String,
}

pub struct RegexAclAuthorizer {
    acls: Vec<AdminAclRuleEntry>,
}

impl TryFrom<RegexAclConfig> for RegexAclAuthorizer {
    type Error = Error;
    fn try_from(config: RegexAclConfig) -> Result<Self> {
        let mut acls = Vec::new();
        for acl in config.acls {
            if !acl.allowed_endpoints.starts_with("^/kbs") || !acl.allowed_endpoints.ends_with("$")
            {
                return Err(Error::UnanchoredRegex);
            }
            let regex = Regex::new(&acl.allowed_endpoints)?;
            acls.push(AdminAclRuleEntry {
                regex,
                role: acl.role,
            });
        }
        Ok(RegexAclAuthorizer { acls })
    }
}

impl AuthorizationTrait for RegexAclAuthorizer {
    fn authorize(&self, claims: Claims, request: &HttpRequest) -> Result<AuthorizationDecision> {
        for acl in &self.acls {
            if claims.role != acl.role {
                continue;
            }

            if acl.regex.is_match(&request.uri().to_string()) {
                return Ok(AuthorizationDecision {
                    allowed: true,
                    reason: "Subject allowed".to_string(),
                });
            }
        }
        Err(Error::AdminAccessDenied {
            reason: format!(
                "Role {} not allowed for path {}",
                claims.role,
                request.uri()
            ),
        })
    }
}
