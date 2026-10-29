// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::HttpRequest;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::admin::{AuthorizationDecision, Claims, authorization::AuthorizationTrait, error::*};

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
        let path = request
            .uri()
            .path_and_query()
            .map(|path| path.as_str())
            .unwrap_or_else(|| request.path());

        for acl in &self.acls {
            if claims.role != acl.role {
                continue;
            }

            if acl.regex.is_match(path) {
                return Ok(AuthorizationDecision {
                    allowed: true,
                    reason: "Subject allowed".to_string(),
                });
            }
        }
        Err(Error::AdminAccessDenied {
            reason: format!("Role {} not allowed for path {}", claims.role, path),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    // HTTP/1.1-style origin-form URI, allowed.
    #[case("^/kbs/.+$", "/kbs/v0/resource-policy", true)]
    // HTTP/2-style absolute-form URI, allowed.
    #[case("^/kbs/.+$", "https://10.57.211.44:30267/kbs/v0/resource-policy", true)]
    // HTTP/2-style absolute-form URI, outside the ACL.
    #[case(
        "^/kbs/v0/allowed/.+$",
        "https://10.57.211.44:30267/kbs/v0/denied/path",
        false
    )]
    // Query string is preserved and matched, regardless of URI form.
    #[case(
        "^/kbs/v0/resource-policy\\?foo=bar$",
        "/kbs/v0/resource-policy?foo=bar",
        true
    )]
    #[case(
        "^/kbs/v0/resource-policy\\?foo=bar$",
        "https://10.57.211.44:30267/kbs/v0/resource-policy?foo=bar",
        true
    )]
    #[case("^/kbs/v0/resource-policy$", "/kbs/v0/resource-policy?foo=bar", false)]
    fn authorize_matches_path_regardless_of_uri_form(
        #[case] allowed_endpoints: &str,
        #[case] uri: &str,
        #[case] expected_allowed: bool,
    ) {
        let config = RegexAclConfig {
            acls: vec![AdminAclRule {
                role: "admin".to_string(),
                allowed_endpoints: allowed_endpoints.to_string(),
            }],
        };
        let authorizer = RegexAclAuthorizer::try_from(config).unwrap();
        let req = actix_web::test::TestRequest::get()
            .uri(uri)
            .to_http_request();
        let claims = Claims {
            role: "admin".to_string(),
        };

        let result = authorizer.authorize(claims, &req);
        assert_eq!(result.is_ok(), expected_allowed);
        if let Err(err) = result {
            assert!(matches!(err, Error::AdminAccessDenied { .. }));
        }
    }
}
