// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::admin::{authorization::AuthorizationTrait, error::*, AuthorizationDecision, Claims};

/// An ACL rule that grants a specific audience access to selected endpoints.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct AdminAclRule {
    // TODO: add more fields here
    /// The admin audience that this rule applies to.
    pub audience: String,

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
    audience: String,
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
                audience: acl.audience,
            });
        }
        Ok(RegexAclAuthorizer { acls })
    }
}

impl AuthorizationTrait for RegexAclAuthorizer {
    fn authorize(&self, claims: Claims, request: &HttpRequest) -> Result<AuthorizationDecision> {
        for acl in &self.acls {
            if !claims.audiences.contains(&acl.audience) {
                continue;
            }

            if acl.regex.is_match(&request.uri().to_string()) {
                return Ok(AuthorizationDecision {
                    allowed: true,
                    reason: "Audience allowed".to_string(),
                });
            }
        }
        Err(Error::AdminAccessDenied {
            reason: "Audience not allowed".to_string(),
        })
    }
}
