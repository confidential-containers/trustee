// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;

pub mod broker;
pub use broker::EarAttestationTokenBroker;

/// default token duration in minutes
pub const DEFAULT_TOKEN_DURATION: i64 = 5;

/// default issuer name
pub const COCO_AS_ISSUER_NAME: &str = "CoCo-Attestation-Service";

/// default profile name carried in the EAR token
pub const DEFAULT_PROFILE: &str = "tag:github.com,2024:confidential-containers/Trustee";

/// default developer name carried in the EAR token
pub const DEFAULT_DEVELOPER_NAME: &str = "https://confidentialcontainers.org";

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenSignerConfig {
    pub key_path: String,
    #[serde(default = "Option::default")]
    pub cert_url: Option<String>,

    // PEM format certificate chain.
    #[serde(default = "Option::default")]
    pub cert_path: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
#[serde(default)]
pub struct EarTokenConfiguration {
    /// The Attestation Results Token duration time (in minutes)
    /// Default: 5 minutes
    pub duration_min: i64,

    /// For tokens, the issuer of the token
    pub issuer_name: String,

    /// The developer name to be used as part of the Verifier ID
    /// in the EAR.
    /// Default: `https://confidentialcontainers.org`
    pub developer_name: String,

    /// The build name to be used as part of the Verifier ID
    /// in the EAR.
    /// The default value will be generated from the Cargo package
    /// name and version of the AS.
    pub build_name: String,

    /// The Profile that describes the EAR token
    /// Default: `tag:github.com,2024:confidential-containers/Trustee`
    pub profile_name: String,

    /// Configuration for signing the EAR
    /// If this is not specified, the EAR
    /// will be signed with an ephemeral private key.
    pub signer: Option<TokenSignerConfig>,
}

impl Default for EarTokenConfiguration {
    fn default() -> Self {
        Self {
            duration_min: DEFAULT_TOKEN_DURATION,
            issuer_name: COCO_AS_ISSUER_NAME.to_string(),
            developer_name: DEFAULT_DEVELOPER_NAME.to_string(),
            build_name: format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            profile_name: DEFAULT_PROFILE.to_string(),
            signer: None,
        }
    }
}
