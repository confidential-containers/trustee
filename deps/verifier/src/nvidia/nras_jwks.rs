// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use jsonwebtoken::jwk::{Jwk, JwkSet};

/// Accessing NRAS requires entering into a licensing agreement with NVIDIA.
/// Using Trustee with the NRAS remote verifier assumes that you have done this.
pub const NRAS_JWKS_URL: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";

#[derive(Clone, Debug)]
pub struct NrasJwks {
    // Mapping of Key Ids to JWKs
    keys: JwkSet,
}

impl NrasJwks {
    pub async fn new() -> Result<Self> {
        let res = reqwest::get(NRAS_JWKS_URL).await?;

        if !res.status().is_success() {
            bail!(
                "JWKS Request Failed with {}. Details: {}",
                res.status(),
                res.text().await?
            )
        };

        let keys = res.json::<JwkSet>().await?;

        Ok(Self { keys })
    }

    pub fn get(&self, kid: String) -> Option<Jwk> {
        self.keys.find(&kid).cloned()
    }
}
