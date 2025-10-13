// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;
use shadow_rs::concatcp;

use crate::config::DEFAULT_WORK_DIR;

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

/// default token work directory
const DEFAULT_TOKEN_WORK_DIR: &str = concatcp!(DEFAULT_WORK_DIR, "/token");

/// default token policy directory
const DEFAULT_POLICY_DIR: &str = concatcp!(DEFAULT_TOKEN_WORK_DIR, "/policies");

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
pub struct EarTokenConfiguration {
    /// The Attestation Results Token duration time (in minutes)
    /// Default: 5 minutes
    #[serde(default = "default_duration")]
    pub duration_min: i64,

    /// For tokens, the issuer of the token
    #[serde(default = "default_issuer_name")]
    pub issuer_name: String,

    /// The developer name to be used as part of the Verifier ID
    /// in the EAR.
    /// Default: `https://confidentialcontainers.org`
    #[serde(default = "default_developer")]
    pub developer_name: String,

    /// The build name to be used as part of the Verifier ID
    /// in the EAR.
    /// The default value will be generated from the Cargo package
    /// name and version of the AS.
    #[serde(default = "default_build")]
    pub build_name: String,

    /// The Profile that describes the EAR token
    /// Default: `tag:github.com,2024:confidential-containers/Trustee`
    #[serde(default = "default_profile")]
    pub profile_name: String,

    /// Configuration for signing the EAR
    /// If this is not specified, the EAR
    /// will be signed with an ephemeral private key.
    #[serde(default = "Option::default")]
    pub signer: Option<TokenSignerConfig>,

    /// The path to the work directory that contains policies
    /// to provision the tokens.
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
}

#[inline]
fn default_duration() -> i64 {
    DEFAULT_TOKEN_DURATION
}

#[inline]
fn default_issuer_name() -> String {
    COCO_AS_ISSUER_NAME.to_string()
}

#[inline]
fn default_developer() -> String {
    DEFAULT_DEVELOPER_NAME.to_string()
}

#[inline]
fn default_profile() -> String {
    DEFAULT_PROFILE.to_string()
}

#[inline]
fn default_build() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

#[inline]
fn default_policy_dir() -> String {
    DEFAULT_POLICY_DIR.to_string()
}

impl Default for EarTokenConfiguration {
    fn default() -> Self {
        Self {
            duration_min: default_duration(),
            issuer_name: default_issuer_name(),
            developer_name: default_developer(),
            build_name: default_build(),
            profile_name: default_profile(),
            signer: None,
            policy_dir: default_policy_dir(),
        }
    }
}
