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
//!   Responses are kept in an optional pluggable cache (see [`Pcs::with_cache`]),
//!   keyed by the endpoint and the collateral requested. Cached collateral is
//!   verified by the quote verification library exactly like fresh collateral;
//!   verifiers retry a failed verification once with [`Pcs::refreshing`] when
//!   [`Pcs::served_from_cache`], so stale or bad entries are replaced.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, LazyLock,
};
use std::time::SystemTime;

use tokio::sync::RwLock;

use thiserror::Error;
use tracing::debug;
use urlencoding::decode as urldecode;

use pluggable_cache::{CacheInstance, CacheKey};
use sha2::{Digest, Sha256};
use tracing::warn;

use super::collateral_service::{
    CollateralData, CollateralService, CollateralType, IntelTee, PcsCollaterals,
    PlatformCollaterals,
};
use super::{QcnlConfig, TcbUpdateType};

static PCS_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);

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
    Send(#[source] reqwest::Error),
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
    cache: Option<CacheInstance>,
    /// Whether to serve collateral from `cache`; fetched collateral is
    /// written to it either way.
    read_cache: bool,
    /// Whether any collateral was served from `cache`.
    cache_hit: AtomicBool,
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
                cache: None,
                read_cache: true,
                cache_hit: AtomicBool::new(false),
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
            cache: None,
            read_cache: true,
            cache_hit: AtomicBool::new(false),
        })
    }

    /// Cache collateral fetched over HTTP in `cache`. The `file://` backend
    /// reads local data and is not cached here.
    pub fn with_cache(mut self, cache: Option<CacheInstance>) -> Self {
        self.cache = cache;
        self
    }

    /// Fetch all collateral afresh, replacing what is cached. Used to retry a
    /// verification that failed with cached collateral, which may be stale.
    pub fn refreshing(mut self) -> Self {
        self.read_cache = false;
        self
    }

    /// Whether any collateral was served from the cache so far.
    pub fn served_from_cache(&self) -> bool {
        self.cache_hit.load(Ordering::Relaxed)
    }

    /// The cache key for `ct` fetched from `url`: a short hash of the
    /// endpoint (so different PCCS instances never share entries), the kind
    /// of collateral and its parameters.
    fn cache_key(&self, url: &url::Url, ct: &CollateralType<'_>) -> Option<CacheKey> {
        let endpoint = &hex::encode(Sha256::digest(url.as_str().as_bytes()))[..16];
        let update = &self.tcb_update_type;
        let key = match ct {
            CollateralType::TcbInfo(tee, fmspc) => {
                format!("{endpoint}/tcb/{tee}/{}/{update}", hex::encode(fmspc))
            }
            CollateralType::QeIdentity(tee) => format!("{endpoint}/qe/{tee}/{update}"),
            CollateralType::PckCrl(ca) => format!("{endpoint}/pckcrl/{ca}"),
            CollateralType::RootCaCrl(cdp) => {
                let cdp = hex::encode(Sha256::digest(cdp.unwrap_or_default().as_bytes()));
                format!("{endpoint}/rootcacrl/{}", &cdp[..16])
            }
        };
        CacheKey::new(key).ok()
    }

    async fn cached(&self, key: &CacheKey) -> Option<CollateralData> {
        if !self.read_cache {
            return None;
        }
        let cache = self.cache.as_ref()?;
        match cache.get(key).await {
            Ok(Some(bytes)) => {
                let data = decode_collateral(&bytes);
                if data.is_none() {
                    warn!("discarding malformed cached collateral {key}");
                    let _ = cache.delete(key).await;
                }
                data
            }
            Ok(None) => None,
            Err(e) => {
                warn!("collateral cache lookup for {key} failed: {e}");
                None
            }
        }
    }

    async fn store(&self, key: &CacheKey, data: &CollateralData) {
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.set(key, encode_collateral(data)).await {
                warn!("failed to cache collateral {key}: {e}");
            }
        }
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
                    (IntelTee::Tdx, TcbUpdateType::Early) => col
                        .tdqeidentity_early
                        .as_ref()
                        .or(col.tdqeidentity.as_ref()),
                    (IntelTee::Tdx, TcbUpdateType::Standard) => col.tdqeidentity.as_ref(),
                    (IntelTee::Sgx, TcbUpdateType::Early) => {
                        col.qeidentity_early.as_ref().or(col.qeidentity.as_ref())
                    }
                    (IntelTee::Sgx, TcbUpdateType::Standard) => col.qeidentity.as_ref(),
                }
                .ok_or_else(|| {
                    debug!("no {:?} qeidentity in {source}", tee);
                    PcsError::Collateral(source.to_string())
                })?;

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

        // Intel's official PCS returns the Root CA CRL as raw DER, fetched
        // directly from the CRL Distribution Point URL embedded in the
        // certificate. Third-party caching services following Intel's spec
        // (https://cc-enabling.trustedservices.intel.com/intel-sgx-tdx-pccs/01/introduction/),
        // always return RootCaCrl hex-encoded so `CollateralService::get` must decode it
        // on return.
        let needs_hex_decode = matches!(ct, CollateralType::RootCaCrl(_)) && !is_pcs;

        let cache_key = self.cache_key(url, &ct);
        if let Some(key) = &cache_key {
            if let Some(data) = self.cached(key).await {
                debug!("collateral cache hit for {key}");
                self.cache_hit.store(true, Ordering::Relaxed);
                return Ok(data);
            }
        }

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

        let response_bytes = response.bytes().await?;
        let body = if needs_hex_decode {
            hex::decode(response_bytes.trim_ascii())?
        } else {
            Vec::from(response_bytes)
        };
        let data = CollateralData { body, cert_chain };
        if let Some(key) = &cache_key {
            self.store(key, &data).await;
        }
        Ok(data)
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

/// `[u32 BE body length][body][u8 has chain][chain]`
fn encode_collateral(data: &CollateralData) -> Vec<u8> {
    let chain = data.cert_chain.as_deref();
    let mut out = Vec::with_capacity(5 + data.body.len() + chain.map_or(0, <[u8]>::len));
    out.extend_from_slice(&(data.body.len() as u32).to_be_bytes());
    out.extend_from_slice(&data.body);
    out.push(chain.is_some() as u8);
    out.extend_from_slice(chain.unwrap_or_default());
    out
}

fn decode_collateral(bytes: &[u8]) -> Option<CollateralData> {
    let len = u32::from_be_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
    let body = bytes.get(4..4 + len)?.to_vec();
    let rest = bytes.get(4 + len..)?;
    let cert_chain = match rest.split_first()? {
        (0, []) => None,
        (1, chain) => Some(chain.to_vec()),
        _ => return None,
    };
    Some(CollateralData { body, cert_chain })
}

fn url_decode_bytes(s: &str) -> Result<Vec<u8>, PcsError> {
    Ok(urldecode(s)?.into_owned().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::{decode_collateral, encode_collateral, CollateralData};

    #[test]
    fn collateral_encoding_round_trip() {
        for cert_chain in [None, Some(vec![]), Some(b"chain".to_vec())] {
            let data = CollateralData {
                body: b"body".to_vec(),
                cert_chain,
            };
            let decoded = decode_collateral(&encode_collateral(&data)).unwrap();
            assert_eq!(decoded.body, data.body);
            assert_eq!(decoded.cert_chain, data.cert_chain);
        }
        assert!(decode_collateral(b"").is_none());
        assert!(decode_collateral(&[0, 0, 0, 9, 1]).is_none());
        assert!(decode_collateral(&[0, 0, 0, 0, 2]).is_none());
    }

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
