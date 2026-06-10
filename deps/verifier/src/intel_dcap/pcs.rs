// Copyright (c) 2026 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0

//! PCS/PCCS collateral client.
//!
//! [`Pcs::new`] inspects the `collateral_service` URL scheme:
//! - `file://` — reads a JSON file written by the Intel DCAP Pcs Client Tool
//!   to a user-provided output path. The deserialized data is cached per path behind
//!   an `Arc<tokio::sync::RwLock<_>>`; the cache is invalidated when the file's mtime changes.
//! - Any other scheme — fetches collateral from a PCS/PCCS HTTPS endpoint.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, LazyLock};
use std::time::SystemTime;

use tokio::sync::RwLock;

use thiserror::Error;
use tracing::debug;
use urlencoding::decode as urldecode;

use http_cache_reqwest::{
    Cache, CacheMode, HttpCache, HttpCacheOptions, MokaCacheBuilder, MokaManager,
};
use reqwest_middleware::ClientBuilder;
use std::time::Duration;

use super::collateral_service::{
    CollateralData, CollateralService, CollateralType, IntelTee, PcsCollaterals,
    PlatformCollaterals,
};
use super::{QcnlConfig, TcbUpdateType};

const PCS_CACHE_MAX_AGE: Duration = Duration::from_secs(168 * 3600);

static PCS_CLIENT: LazyLock<reqwest_middleware::ClientWithMiddleware> = LazyLock::new(|| {
    ClientBuilder::new(reqwest::Client::new())
        .with(Cache(HttpCache {
            mode: CacheMode::ForceCache,
            manager: MokaManager::new(MokaCacheBuilder::new(1024).build()),
            options: HttpCacheOptions {
                cache_status_headers: true,
                max_ttl: Some(PCS_CACHE_MAX_AGE),
                ..Default::default()
            },
        }))
        .build()
});

struct Cached {
    data: Arc<PcsCollaterals>,
    mtime: SystemTime,
}

static FILE_CACHE: LazyLock<RwLock<HashMap<PathBuf, Cached>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

enum PcsInner {
    Http { url: url::Url, is_pcs: bool },
    File { path: PathBuf },
}

#[derive(Error, Debug)]
pub enum PcsError {
    #[error("unexpected HTTP response from PCS: {0}")]
    Response(#[from] reqwest::Error),
    #[error("failed to send request to PCS: {0}")]
    Send(#[from] reqwest_middleware::Error),
    #[error("invalid collateral service URL: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("collateral file I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("collateral JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to decode collateral data: {0}")]
    Decoding(String),
    #[error("collateral not available from {0}")]
    Collateral(String),
    #[error("PCS internal error: {0}")]
    Internal(&'static str),
}

impl From<std::string::FromUtf8Error> for PcsError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        PcsError::Decoding(e.to_string())
    }
}

impl From<hex::FromHexError> for PcsError {
    fn from(e: hex::FromHexError) -> Self {
        PcsError::Decoding(e.to_string())
    }
}

pub struct Pcs {
    inner: PcsInner,
    tcb_update_type: TcbUpdateType,
}

impl Pcs {
    pub fn new(config: &QcnlConfig) -> Result<Self, PcsError> {
        let tcb_update_type = config.tcb_update_type.clone();
        let url = url::Url::parse(&config.collateral_service)?;

        if url.scheme() == "file" {
            let path = url.to_file_path().map_err(|_| {
                PcsError::Internal("file:// URL cannot be converted to a valid path")
            })?;
            return Ok(Self {
                inner: PcsInner::File { path },
                tcb_update_type,
            });
        }

        let is_pcs = url.host_str() == Some("api.trustedservices.intel.com");

        // Strip path — endpoints are built from scratch in get_from_http().
        let mut base = url.clone();
        base.set_path("/");
        base.set_query(None);

        Ok(Self {
            inner: PcsInner::Http { url: base, is_pcs },
            tcb_update_type,
        })
    }

    fn cert_chain_header(ct: &CollateralType<'_>) -> Option<&'static str> {
        match ct {
            CollateralType::TcbInfo(..) => Some("tcb-info-issuer-chain"),
            CollateralType::QeIdentity(..) => Some("sgx-enclave-identity-issuer-chain"),
            CollateralType::PckCrl(..) => Some("sgx-pck-crl-issuer-chain"),
            CollateralType::RootCaCrl(_) => None,
        }
    }

    async fn load_collaterals(path: &PathBuf) -> Result<Arc<PcsCollaterals>, PcsError> {
        let mtime = tokio::fs::metadata(path)
            .await
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    debug!("collateral file not found: {}", path.display());
                    PcsError::Collateral(path.display().to_string())
                } else {
                    PcsError::Io(e)
                }
            })?
            .modified()?;

        {
            let guard = FILE_CACHE.read().await;
            if let Some(cached) = guard.get(path) {
                if cached.mtime == mtime {
                    return Ok(cached.data.clone());
                }
            }
        }

        let text = tokio::fs::read_to_string(path).await?;
        let pc: PlatformCollaterals = serde_json::from_str(&text)?;
        let data = Arc::new(pc.collaterals);

        let mut guard = FILE_CACHE.write().await;
        // Re-check: another task may have populated the cache while we were loading.
        if let Some(cached) = guard.get(path) {
            if cached.mtime == mtime {
                return Ok(cached.data.clone());
            }
        }
        guard.insert(
            path.clone(),
            Cached {
                data: data.clone(),
                mtime,
            },
        );
        Ok(data)
    }

    async fn get_from_file(&self, ct: CollateralType<'_>) -> Result<CollateralData, PcsError> {
        let PcsInner::File { path } = &self.inner else {
            return Err(PcsError::Internal("get_from_file called on HTTP backend"));
        };
        let source = path.display();
        let col = Self::load_collaterals(path).await?;

        match ct {
            CollateralType::TcbInfo(tee, fmspc) => {
                let entry = col
                    .tcbinfos
                    .iter()
                    .find(|e| e.fmspc == fmspc)
                    .ok_or_else(|| {
                        debug!("fmspc {:02x?} not found in {source}", fmspc);
                        PcsError::Collateral(source.to_string())
                    })?;

                let tcb_info = match (tee, &self.tcb_update_type) {
                    (IntelTee::Tdx, TcbUpdateType::Early) => entry
                        .tdx_tcbinfo_early
                        .as_ref()
                        .or(entry.tdx_tcbinfo.as_ref()),
                    (IntelTee::Tdx, TcbUpdateType::Standard) => entry.tdx_tcbinfo.as_ref(),
                    (IntelTee::Sgx, TcbUpdateType::Early) => entry
                        .sgx_tcbinfo_early
                        .as_ref()
                        .or(entry.sgx_tcbinfo.as_ref()),
                    (IntelTee::Sgx, TcbUpdateType::Standard) => entry.sgx_tcbinfo.as_ref(),
                }
                .ok_or_else(|| {
                    debug!("no {:?} tcbinfo for fmspc {:02x?} in {source}", tee, fmspc);
                    PcsError::Collateral(source.to_string())
                })?;

                Ok(CollateralData {
                    body: serde_json::to_vec(tcb_info)?,
                    cert_chain: Some(url_decode_bytes(&col.certificates.tcb_info_issuer_chain)?),
                })
            }

            CollateralType::QeIdentity(tee) => {
                let body = match (tee, &self.tcb_update_type) {
                    (IntelTee::Tdx, TcbUpdateType::Early) => {
                        col.tdqeidentity_early.as_ref().unwrap_or(&col.tdqeidentity)
                    }
                    (IntelTee::Tdx, _) => &col.tdqeidentity,
                    (IntelTee::Sgx, TcbUpdateType::Early) => {
                        col.qeidentity_early.as_ref().unwrap_or(&col.qeidentity)
                    }
                    (IntelTee::Sgx, _) => &col.qeidentity,
                };

                Ok(CollateralData {
                    body: serde_json::to_vec(body)?,
                    cert_chain: Some(url_decode_bytes(
                        &col.certificates.enclave_identity_issuer_chain,
                    )?),
                })
            }

            CollateralType::PckCrl(ca) => {
                let chains = col
                    .certificates
                    .pck_crl_issuer_chains
                    .as_ref()
                    .ok_or_else(|| {
                        debug!("no PCK CRL issuer chains in {source}");
                        PcsError::Collateral(source.to_string())
                    })?;

                let crl_hex = &col.pckcacrl[&ca];
                let chain_pem = &chains[&ca];

                Ok(CollateralData {
                    body: hex::decode(crl_hex)?,
                    cert_chain: Some(url_decode_bytes(chain_pem)?),
                })
            }

            // Use rootcacrl from the file directly, but validate the CDP matches
            // what was extracted from the certificate chain.
            CollateralType::RootCaCrl(crl_distpoint) => {
                if let (Some(requested), Some(stored)) = (crl_distpoint, &col.rootcacrl_cdp) {
                    if requested != stored {
                        debug!("rootcacrl_cdp mismatch: {source} has {stored}, certificate has {requested}");
                        return Err(PcsError::Collateral(source.to_string()));
                    }
                }
                Ok(CollateralData {
                    body: hex::decode(&col.rootcacrl)?,
                    cert_chain: None,
                })
            }
        }
    }

    async fn get_from_http(&self, ct: CollateralType<'_>) -> Result<CollateralData, PcsError> {
        let PcsInner::Http { url, is_pcs } = &self.inner else {
            return Err(PcsError::Internal("get_from_http called on file backend"));
        };
        let source = url.as_str();
        let is_pcs = *is_pcs;
        let mut params: HashMap<&str, String> = HashMap::new();
        let chain_header = Self::cert_chain_header(&ct);

        let mut endpoint = match ct {
            CollateralType::TcbInfo(tee, fmspc) => {
                params.insert("fmspc", hex::encode_upper(fmspc));
                params.insert("update", self.tcb_update_type.to_string());
                url.join(&format!("{tee}/certification/v4/tcb"))
                    .map_err(PcsError::UrlParse)?
            }
            CollateralType::QeIdentity(tee) => {
                params.insert("update", self.tcb_update_type.to_string());
                url.join(&format!("{tee}/certification/v4/qe/identity"))
                    .map_err(PcsError::UrlParse)?
            }
            CollateralType::PckCrl(ca) => {
                params.insert("ca", ca.to_string());
                params.insert("encoding", "der".into());
                url.join("sgx/certification/v4/pckcrl")
                    .map_err(PcsError::UrlParse)?
            }
            CollateralType::RootCaCrl(crl_distpoint) => {
                if is_pcs {
                    let crl = crl_distpoint.ok_or_else(|| {
                        debug!(
                            "CRL distribution point not found in certificate chain for {source}"
                        );
                        PcsError::Collateral(source.to_string())
                    })?;
                    url::Url::parse(crl).map_err(PcsError::UrlParse)?
                } else {
                    url.join("sgx/certification/v4/rootcacrl")
                        .map_err(PcsError::UrlParse)?
                }
            }
        };

        endpoint.query_pairs_mut().extend_pairs(params.iter());

        let response = PCS_CLIENT
            .get(endpoint)
            .send()
            .await
            .map_err(PcsError::Send)?
            .error_for_status()
            .map_err(|e| {
                if let Some(status) = e.status() {
                    if status == reqwest::StatusCode::NOT_FOUND
                        || status == reqwest::StatusCode::GONE
                    {
                        let url = e.url().map(|u| u.as_str()).unwrap_or(source);
                        debug!("HTTP {status} from {url}");
                        return PcsError::Collateral(url.to_string());
                    }
                }
                PcsError::Response(e)
            })?;

        let cert_chain = chain_header
            .and_then(|h| response.headers().get(h))
            .and_then(|v| v.to_str().ok())
            .map(url_decode_bytes)
            .transpose()?;

        let body = Vec::from(response.bytes().await?);
        Ok(CollateralData { body, cert_chain })
    }
}

impl CollateralService for Pcs {
    type Error = PcsError;

    async fn get(&self, ct: CollateralType<'_>) -> Result<CollateralData, PcsError> {
        match &self.inner {
            PcsInner::File { .. } => self.get_from_file(ct).await,
            PcsInner::Http { .. } => self.get_from_http(ct).await,
        }
    }
}

fn url_decode_bytes(s: &str) -> Result<Vec<u8>, PcsError> {
    Ok(urldecode(s)?.into_owned().into_bytes())
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    #[ignore = "requires PCS network connectivity; run with: cargo test -p verifier --no-default-features --features tdx-verifier -- tcb_info_signature --include-ignored"]
    async fn tcb_info_signature() {
        use super::{CollateralService, CollateralType, Pcs};
        use crate::intel_dcap::{
            collateral_service::{CollateralData, IntelTee, TcbInfoJson},
            QcnlConfig,
        };
        use openssl::bn::BigNum;
        use openssl::ec::EcKey;
        use openssl::ecdsa::EcdsaSig;
        use openssl::sha::sha256;
        use openssl::x509::X509;
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let pcs = Pcs::new(&QcnlConfig::default()).expect("Pcs::new");
        let CollateralData {
            body: tcb,
            cert_chain: chain,
        } = pcs
            .get(CollateralType::TcbInfo(
                &IntelTee::Tdx,
                [0x90, 0xC0, 0x6F, 0x00, 0x00, 0x00],
            ))
            .await
            .expect("get TcbInfo from PCS");

        assert!(!tcb.is_empty());
        assert!(chain.is_some());

        let chain =
            X509::stack_from_pem(chain.unwrap().as_slice()).expect("parse TcbInfo signing certs");
        assert_eq!(chain.len(), 2);

        let d: TcbInfoJson =
            serde_json::from_slice(tcb.as_slice()).expect("deserialize TcbInfoJson");
        assert_eq!(d.signature.len(), 64);

        let public_key = chain[0]
            .public_key()
            .expect("get public key from signing cert");
        let r = BigNum::from_slice(&d.signature[..32]).expect("signature R");
        let s = BigNum::from_slice(&d.signature[32..]).expect("signature S");
        let ecdsa_sig = EcdsaSig::from_private_components(r, s).expect("build EcdsaSig");

        let bytes = serde_json::to_vec(&d.tcb_info).expect("serialize tcbInfo for verification");
        let ec_key = EcKey::try_from(public_key).expect("extract EC key");

        assert!(ecdsa_sig
            .verify(&sha256(bytes.as_slice()), &ec_key)
            .is_ok_and(|res| res));
    }
}
