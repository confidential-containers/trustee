// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use serde::Deserialize;
use std::fmt;
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::RwLock;

mod coco;

pub trait AttestationTokenVerifier {
    /// Verify an signed attestation token.
    /// Returns the custom claims JSON string of the token.
    fn verify(&self, token: String) -> Result<String>;
}

#[derive(Deserialize, Debug, Clone, EnumString)]
pub enum AttestationTokenVerifierType {
    CoCo,
}

impl AttestationTokenVerifierType {
    pub fn to_token_verifier(
        &self,
    ) -> Result<Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>> {
        match self {
            AttestationTokenVerifierType::CoCo => Ok(Arc::new(RwLock::new(
                coco::CoCoAttestationTokenVerifier::default(),
            ))
                as Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>),
        }
    }
}

impl fmt::Display for AttestationTokenVerifierType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}
