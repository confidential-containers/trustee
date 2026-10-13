// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use pluggable_cache::{CacheInstance, CacheKey};
use reqwest::Url;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

/// Accessing NRAS requires entering into a licensing agreement with NVIDIA.
/// Using Trustee with the NRAS remote verifier assumes that you have done this.
pub const NRAS_JWKS_URL: &str = "https://nras.attestation.nvidia.com/.well-known/jwks.json";

/// Cache namespace for the NRAS token signing key set.
pub const NRAS_JWKS_CACHE_NAMESPACE: &str = "nvidia_nras_jwks";

/// Timeout for fetching the NRAS JWKS. Unlike an attestation request this is
/// just a small, static document download with no server-side work, so a
/// tighter budget than NRAS_ATTESTATION_TIMEOUT is sufficient.
const NRAS_JWKS_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Debug)]
pub struct NrasJwks {
    // Mapping of Key Ids to JWKs
    keys: JwkSet,
}

impl NrasJwks {
    /// Load the key set for `url` from `cache`, fetching and caching it on a
    /// miss or if `refresh` is set.
    ///
    /// The key set is a trust anchor that cannot be verified independently,
    /// so its namespace should only be backed by storage trusted as much as
    /// the configuration itself.
    pub async fn load(cache: &CacheInstance, url: &str, refresh: bool) -> Result<Self> {
        let key = CacheKey::new(hex::encode(Sha256::digest(url.as_bytes())))?;
        let url = Self::parse_url(url)?;
        if !refresh {
            match cache.get(&key).await {
                Ok(Some(bytes)) => match serde_json::from_slice::<JwkSet>(&bytes) {
                    Ok(keys) => {
                        debug!("NRAS JWKS loaded from cache");
                        return Ok(Self { keys });
                    }
                    Err(e) => {
                        warn!("discarding malformed cached NRAS JWKS: {e}");
                        let _ = cache.delete(&key).await;
                    }
                },
                Ok(None) => {}
                Err(e) => warn!("NRAS JWKS cache lookup failed: {e}"),
            }
        }

        let bytes = Self::download(url).await?;
        let keys: JwkSet = serde_json::from_slice(&bytes).context("Failed to parse NRAS JWKS")?;
        if let Err(e) = cache.set(&key, bytes).await {
            warn!("failed to cache NRAS JWKS: {e}");
        }
        Ok(Self { keys })
    }

    /// The key set is the trust root for NRAS results; never accept it over
    /// an unauthenticated channel.
    fn parse_url(url: &str) -> Result<Url> {
        let parsed = Url::parse(url).with_context(|| format!("Invalid NRAS JWKS URL: {url}"))?;
        if parsed.scheme() != "https" {
            bail!("NRAS JWKS URL must use https: {url}");
        }
        Ok(parsed)
    }

    async fn download(url: Url) -> Result<Vec<u8>> {
        // https_only also rejects redirects to plain http.
        let client = reqwest::Client::builder()
            .https_only(true)
            .timeout(NRAS_JWKS_TIMEOUT)
            .build()?;
        let res = client.get(url).send().await?;

        if !res.status().is_success() {
            bail!(
                "JWKS Request Failed with {}. Details: {}",
                res.status(),
                res.text().await?
            )
        };

        Ok(res.bytes().await?.to_vec())
    }

    pub fn get(&self, kid: String) -> Option<Jwk> {
        self.keys.find(&kid).cloned()
    }

    pub fn contains(&self, kid: &str) -> bool {
        self.keys.find(kid).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pluggable_cache::memory::{Config, MemoryCache};
    use std::sync::Arc;

    const JWKS: &str = r#"{"keys":[{"kty":"EC","crv":"P-384","kid":"k1","x":"AAAA","y":"AAAA"}]}"#;

    #[tokio::test]
    async fn served_from_cache_without_network() {
        let cache: CacheInstance = Arc::new(MemoryCache::new(&Config::default()).unwrap());
        // An unreachable URL proves no request is made on a hit.
        let url = "https://127.0.0.1:1/jwks.json";
        let key = CacheKey::new(hex::encode(Sha256::digest(url.as_bytes()))).unwrap();
        cache.set(&key, JWKS.as_bytes().to_vec()).await.unwrap();

        let jwks = NrasJwks::load(&cache, url, false).await.unwrap();
        assert!(jwks.contains("k1"));
        assert!(
            NrasJwks::load(&cache, url, true).await.is_err(),
            "refresh hits the network"
        );
    }

    #[test]
    fn rejects_plain_http() {
        assert!(NrasJwks::parse_url("https://example.com/jwks.json").is_ok());
        assert!(NrasJwks::parse_url("http://example.com/jwks.json").is_err());
        assert!(NrasJwks::parse_url("not a url").is_err());
    }

    #[tokio::test]
    async fn malformed_cache_entry_is_dropped() {
        let cache: CacheInstance = Arc::new(MemoryCache::new(&Config::default()).unwrap());
        let url = "https://127.0.0.1:1/jwks.json";
        let key = CacheKey::new(hex::encode(Sha256::digest(url.as_bytes()))).unwrap();
        cache.set(&key, b"not json".to_vec()).await.unwrap();

        assert!(NrasJwks::load(&cache, url, false).await.is_err());
        assert_eq!(cache.get(&key).await.unwrap(), None);
    }
}
