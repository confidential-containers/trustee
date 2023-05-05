// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::RwLock;

mod simple;

pub trait AttestationTokenBroker {
    /// Issue an signed attestation token with custom claims.
    /// Return base64 encoded Token.
    fn issue(&self, custom_claims: Value, duration_min: usize) -> Result<String>;

    /// Verify an signed attestation token.
    /// Returns the custom claims JSON string of the token.
    fn verify(&self, token: String) -> Result<String>;

    /// Get the X.509 formatted certificate chain of the attestation token broker.
    /// Returns the certificate chain in JWKS format (https://www.rfc-editor.org/rfc/rfc7517#appendix-B).
    fn x509_certificate_chain(&self) -> Result<String>;
}

#[derive(Deserialize, Debug, Clone, EnumString)]
pub enum AttestationTokenBrokerType {
    Simple,
}

impl AttestationTokenBrokerType {
    pub fn to_token_broker(&self) -> Result<Arc<RwLock<dyn AttestationTokenBroker + Send + Sync>>> {
        match self {
            AttestationTokenBrokerType::Simple => Ok(Arc::new(RwLock::new(
                simple::SimpleAttestationTokenBroker::new()?,
            ))
                as Arc<RwLock<dyn AttestationTokenBroker + Send + Sync>>),
        }
    }
}
