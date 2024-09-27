// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use serde::Deserialize;
use serde_json::Value;
use strum::{Display, EnumString};

mod simple;

pub const COCO_AS_ISSUER_NAME: &str = "CoCo-Attestation-Service";
pub const DEFAULT_TOKEN_TIMEOUT: i64 = 5;

pub trait AttestationTokenBroker {
    /// Issue an signed attestation token with custom claims.
    /// Return base64 encoded Json Web Token.
    fn issue(&self, custom_claims: Value) -> Result<String>;

    /// Get the public keys and X.509 formatted certificate chain of the attestation token broker.
    /// Returns the certificate chain in [JWKS format](https://www.rfc-editor.org/rfc/rfc7517#appendix-B).
    fn pubkey_jwks(&self) -> Result<String>;
}

#[derive(Deserialize, Debug, Clone, EnumString, Display, PartialEq)]
pub enum AttestationTokenBrokerType {
    Simple,
}

impl AttestationTokenBrokerType {
    pub fn to_token_broker(
        &self,
        config: AttestationTokenConfig,
    ) -> Result<Box<dyn AttestationTokenBroker + Send + Sync>> {
        match self {
            AttestationTokenBrokerType::Simple => {
                Ok(Box::new(simple::SimpleAttestationTokenBroker::new(config)?)
                    as Box<dyn AttestationTokenBroker + Send + Sync>)
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct AttestationTokenConfig {
    /// The Attestation Result Token duration time(in minute)
    #[serde(default = "default_duration_min")]
    pub duration_min: i64,

    #[serde(default = "default_issuer_name")]
    pub issuer_name: String,

    pub signer: Option<TokenSignerConfig>,
}

fn default_duration_min() -> i64 {
    DEFAULT_TOKEN_TIMEOUT
}

fn default_issuer_name() -> String {
    COCO_AS_ISSUER_NAME.to_string()
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenSignerConfig {
    pub key_path: String,
    pub cert_url: Option<String>,

    // PEM format certificate chain.
    pub cert_path: Option<String>,
}

impl Default for AttestationTokenConfig {
    fn default() -> Self {
        Self {
            duration_min: DEFAULT_TOKEN_TIMEOUT,
            issuer_name: COCO_AS_ISSUER_NAME.to_string(),
            signer: None,
        }
    }
}
