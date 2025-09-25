// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use std::collections::HashMap;

/// Accessing NRAS requires entering into a licensing agreement with NVIDIA.
/// Using Trustee with the NRAS remote verifier assumes that you have done this.
pub const NRAS_JWKS_URL: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";

#[derive(Clone, Debug)]
pub struct NrasJwks {
    // Mapping of Key Ids to JWKs
    keys: HashMap<String, String>,
}

impl NrasJwks {
    pub async fn new() -> Result<Self> {
        let mut keys = HashMap::new();

        let res = reqwest::get(NRAS_JWKS_URL).await?;

        if !res.status().is_success() {
            bail!(
                "JWKS Request Failed with {}. Details: {}",
                res.status(),
                res.text().await?
            )
        };

        let loaded_keys: serde_json::Value = res.json().await?;
        let loaded_keys = loaded_keys
            .pointer("/keys")
            .ok_or_else(|| anyhow!("Could not find JWKs"))?;
        let loaded_keys = loaded_keys
            .as_array()
            .ok_or_else(|| anyhow!("Could not find JWKs array"))?;

        // TODO: check cert chain and expiration of each key
        for loaded_key in loaded_keys {
            let kid = loaded_key
                .pointer("/kid")
                .ok_or_else(|| anyhow!("Could not find KID"))?;
            let kid = kid.as_str().ok_or_else(|| anyhow!("Malformed KID"))?;

            keys.insert(kid.to_string(), serde_json::to_string(loaded_key)?);
        }

        Ok(Self { keys })
    }

    pub fn get(&self, kid: String) -> Option<String> {
        self.keys.get(&kid).cloned()
    }
}
