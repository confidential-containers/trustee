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

/// Top-level URI namespaces that an admin ACL may target. Admin authentication is
/// intentionally limited to the KBS API (`/kbs`) and the optional admin-protected
/// Prometheus endpoint (`/metrics`), so that relaxing the anchoring check cannot
/// silently extend it to arbitrary endpoints. A rule spanning both namespaces must
/// be split into one [`AdminAclRule`] per namespace.
const ALLOWED_ENDPOINT_PREFIXES: [&str; 2] = ["^/kbs", "^/metrics"];

pub struct RegexAclAuthorizer {
    acls: Vec<AdminAclRuleEntry>,
}

impl TryFrom<RegexAclConfig> for RegexAclAuthorizer {
    type Error = Error;
    fn try_from(config: RegexAclConfig) -> Result<Self> {
        let mut acls = Vec::new();
        for acl in config.acls {
            let anchored = acl.allowed_endpoints.ends_with('$');
            let known_namespace = ALLOWED_ENDPOINT_PREFIXES
                .iter()
                .any(|prefix| acl.allowed_endpoints.starts_with(prefix));
            if !known_namespace || !anchored {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config(allowed_endpoints: &str) -> RegexAclConfig {
        RegexAclConfig {
            acls: vec![AdminAclRule {
                role: "admin".to_string(),
                allowed_endpoints: allowed_endpoints.to_string(),
            }],
        }
    }

    #[test]
    fn accepts_anchored_kbs_and_metrics_regexes() {
        for allowed in ["^/kbs/.+$", "^/kbs/v0/resource/.+$", "^/metrics$"] {
            assert!(
                RegexAclAuthorizer::try_from(config(allowed)).is_ok(),
                "expected {allowed} to be accepted"
            );
        }
    }

    #[test]
    fn rejects_unanchored_or_unknown_namespace_regexes() {
        for rejected in [
            "metrics$",       // not anchored at the start
            "^/metrics",      // not anchored at the end
            "^/kbs/v0/.+",    // not anchored at the end
            "^/resource/.+$", // unknown top-level namespace
            "^/healthz$",     // health endpoints are not admin-scoped
            "^/.*$",          // would grant every path
        ] {
            assert!(
                matches!(
                    RegexAclAuthorizer::try_from(config(rejected)),
                    Err(Error::UnanchoredRegex)
                ),
                "expected {rejected} to be rejected"
            );
        }
    }
}
