// Copyright (c) 2025 by Red Hat.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Shared TLS configuration helpers for KBS and its companion services.
//!
//! The top-level items configure OpenSSL-based listeners with PQC hybrid key
//! exchange groups.  The optional [`grpc`] module (enabled by the `grpc`
//! feature) provides helpers for tonic gRPC client and server TLS.

use std::sync::OnceLock;

use openssl::ssl::{SslAcceptor, SslAcceptorBuilder, SslMethod, SslVersion};
use thiserror::Error;
use tracing::{debug, info, warn};

// X448MLKEM1024 is intentionally omitted: it is not officially standardized and
// remains experimental — not yet accepted by IETF or NIST as a hybrid group.
const PQC_CANDIDATES: &[&str] = &[
    "X25519MLKEM768",
    "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024",
];

const CLASSICAL_GROUPS: &str = "X25519:secp256r1:secp384r1";

static SUPPORTED_PQC_GROUPS: OnceLock<Vec<&'static str>> = OnceLock::new();

#[derive(Error, Debug)]
pub enum PqcTlsError {
    #[error(
        "PQC TLS is required but no PQC groups are supported by OpenSSL (tried: {candidates:?})"
    )]
    PqcRequired { candidates: &'static [&'static str] },

    #[error("Failed to set TLS groups list '{groups}': {source}")]
    SetGroupsFailed {
        groups: String,
        source: openssl::error::ErrorStack,
    },

    #[error("Failed to set minimum TLS protocol version: {0}")]
    SetMinVersionFailed(openssl::error::ErrorStack),
}

#[derive(Debug, Clone)]
pub struct PqcGroupsResult {
    pub pqc_groups: Vec<&'static str>,
    pub groups_list: String,
}

impl PqcGroupsResult {
    pub fn has_pqc(&self) -> bool {
        !self.pqc_groups.is_empty()
    }
}

pub(crate) fn detect_supported_pqc_groups() -> &'static [&'static str] {
    SUPPORTED_PQC_GROUPS.get_or_init(|| {
        let mut supported = Vec::new();
        for &candidate in PQC_CANDIDATES {
            // A fresh builder per candidate avoids state from a failed
            // set_groups_list call leaking into the next probe.
            let mut builder = match SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to create SSL acceptor for PQC detection: {e}");
                    return Vec::new();
                }
            };
            if builder.set_groups_list(candidate).is_ok() {
                debug!("PQC group supported: {candidate}");
                supported.push(candidate);
            }
        }
        if supported.is_empty() {
            info!("No PQC groups supported by OpenSSL (probed: {PQC_CANDIDATES:?})");
        }
        supported
    })
}

pub fn configure_pqc_groups(
    builder: &mut SslAcceptorBuilder,
    require_pqc: bool,
) -> Result<PqcGroupsResult, PqcTlsError> {
    let pqc_groups = detect_supported_pqc_groups();

    if pqc_groups.is_empty() && require_pqc {
        return Err(PqcTlsError::PqcRequired {
            candidates: PQC_CANDIDATES,
        });
    }

    let groups_list = if pqc_groups.is_empty() {
        warn!("PQC TLS not available, using classical groups: {CLASSICAL_GROUPS}");
        CLASSICAL_GROUPS.to_string()
    } else if require_pqc {
        let pqc_only = pqc_groups.join(":");
        info!("PQC TLS enforced (PQC-only, no classical fallback): {pqc_only}");
        pqc_only
    } else {
        let pqc_part = pqc_groups.join(":");
        let full = format!("{pqc_part}:{CLASSICAL_GROUPS}");
        info!("PQC TLS enabled with classical fallback: {full}");
        full
    };

    builder
        .set_groups_list(&groups_list)
        .map_err(|e| PqcTlsError::SetGroupsFailed {
            groups: groups_list.clone(),
            source: e,
        })?;

    if require_pqc {
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(PqcTlsError::SetMinVersionFailed)?;
    }

    Ok(PqcGroupsResult {
        pqc_groups: pqc_groups.to_vec(),
        groups_list,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::ssl::{SslAcceptor, SslMethod};

    fn fresh_builder() -> SslAcceptorBuilder {
        SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap()
    }

    #[test]
    fn pqc_groups_require_false_never_errors() {
        // require_pqc=false must succeed regardless of PQC availability.
        let mut builder = fresh_builder();
        assert!(configure_pqc_groups(&mut builder, false).is_ok());
    }

    #[test]
    fn groups_list_always_includes_classical_fallback() {
        // Classical groups must always appear in the output when require_pqc=false,
        // whether PQC is available or not.
        let mut builder = fresh_builder();
        let result = configure_pqc_groups(&mut builder, false).unwrap();
        assert!(
            result.groups_list.contains(CLASSICAL_GROUPS),
            "groups_list {:?} does not contain classical groups {:?}",
            result.groups_list,
            CLASSICAL_GROUPS
        );
    }

    #[test]
    fn require_pqc_true_behaves_correctly_for_environment() {
        // Inspect what this OpenSSL build actually supports, then assert the
        // correct branch — both paths are reachable depending on the environment.
        let supported = detect_supported_pqc_groups();
        let mut builder = fresh_builder();

        if supported.is_empty() {
            // No PQC support: must return PqcRequired error.
            let err = configure_pqc_groups(&mut builder, true)
                .expect_err("expected PqcRequired when PQC is unavailable");
            assert!(
                matches!(err, PqcTlsError::PqcRequired { .. }),
                "unexpected error variant: {err}"
            );
        } else {
            // PQC available: must succeed with PQC-only groups (no classical fallback).
            let result = configure_pqc_groups(&mut builder, true)
                .expect("expected Ok when PQC is available and require_pqc=true");
            assert!(result.has_pqc(), "has_pqc() must be true when PQC groups are supported");
            assert!(
                !result.groups_list.contains("X25519:"),
                "groups_list must not contain classical groups when require_pqc=true, got: {:?}",
                result.groups_list
            );
            // At least one PQC candidate must appear in the groups list.
            assert!(
                PQC_CANDIDATES.iter().any(|g| result.groups_list.contains(g)),
                "groups_list {:?} contains no PQC candidate",
                result.groups_list
            );
        }
    }

    #[cfg(feature = "grpc")]
    mod grpc_tests {
        use super::super::grpc::{
            build_grpc_client_tls_config, build_grpc_server_tls_config, GrpcTlsMode,
        };
        use std::io::Write as _;

        // Generate a self-signed EC P-256 certificate and private key in PEM format.
        fn test_cert_and_key_pem() -> (Vec<u8>, Vec<u8>) {
            use openssl::asn1::Asn1Time;
            use openssl::bn::{BigNum, MsbOption};
            use openssl::ec::{EcGroup, EcKey};
            use openssl::hash::MessageDigest;
            use openssl::nid::Nid;
            use openssl::pkey::PKey;
            use openssl::x509::{X509Builder, X509NameBuilder};

            let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
            let ec_key = EcKey::generate(&group).unwrap();
            let pkey = PKey::from_ec_key(ec_key).unwrap();

            let mut name = X509NameBuilder::new().unwrap();
            name.append_entry_by_text("CN", "tls-config-test").unwrap();
            let name = name.build();

            let mut serial = BigNum::new().unwrap();
            serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();

            let mut x509 = X509Builder::new().unwrap();
            x509.set_version(2).unwrap();
            x509.set_subject_name(&name).unwrap();
            x509.set_issuer_name(&name).unwrap();
            x509.set_pubkey(&pkey).unwrap();
            x509.set_serial_number(&serial.to_asn1_integer().unwrap()).unwrap();
            x509.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
            x509.set_not_after(&Asn1Time::days_from_now(1).unwrap()).unwrap();
            x509.sign(&pkey, MessageDigest::sha256()).unwrap();

            (x509.build().to_pem().unwrap(), pkey.private_key_to_pem_pkcs8().unwrap())
        }

        #[test]
        fn grpc_tls_mode_default_is_insecure() {
            assert_eq!(GrpcTlsMode::default(), GrpcTlsMode::Insecure);
        }

        #[tokio::test]
        async fn client_tls_insecure_returns_none() {
            let result = build_grpc_client_tls_config(&GrpcTlsMode::Insecure, None).await;
            assert!(matches!(result, Ok(None)));
        }

        #[tokio::test]
        async fn client_tls_tls_no_ca_cert_errors() {
            let result = build_grpc_client_tls_config(&GrpcTlsMode::Tls, None).await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn client_tls_tls_missing_file_errors() {
            let result = build_grpc_client_tls_config(
                &GrpcTlsMode::Tls,
                Some(std::path::Path::new("/nonexistent/ca.crt")),
            )
            .await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn client_tls_tls_with_valid_cert_returns_some() {
            let (cert_pem, _) = test_cert_and_key_pem();
            let mut tmp = tempfile::NamedTempFile::new().unwrap();
            tmp.write_all(&cert_pem).unwrap();
            let result = build_grpc_client_tls_config(&GrpcTlsMode::Tls, Some(tmp.path())).await;
            assert!(matches!(result, Ok(Some(_))));
        }

        #[tokio::test]
        async fn server_tls_both_none_returns_none() {
            let result = build_grpc_server_tls_config(None, None).await;
            assert!(matches!(result, Ok(None)));
        }

        #[tokio::test]
        async fn server_tls_cert_only_errors() {
            let result = build_grpc_server_tls_config(
                Some(std::path::Path::new("/any/cert.pem")),
                None,
            )
            .await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn server_tls_key_only_errors() {
            let result = build_grpc_server_tls_config(
                None,
                Some(std::path::Path::new("/any/key.pem")),
            )
            .await;
            assert!(result.is_err());
        }

        #[tokio::test]
        async fn server_tls_with_valid_cert_and_key_returns_some() {
            let (cert_pem, key_pem) = test_cert_and_key_pem();
            let mut cert_tmp = tempfile::NamedTempFile::new().unwrap();
            let mut key_tmp = tempfile::NamedTempFile::new().unwrap();
            cert_tmp.write_all(&cert_pem).unwrap();
            key_tmp.write_all(&key_pem).unwrap();
            let result =
                build_grpc_server_tls_config(Some(cert_tmp.path()), Some(key_tmp.path())).await;
            assert!(matches!(result, Ok(Some(_))));
        }
    }
}

#[cfg(feature = "grpc")]
pub mod grpc {
    use std::path::Path;

    use anyhow::{Context, Result};
    use tonic::transport::{Certificate, ClientTlsConfig, Identity, ServerTlsConfig};

    /// TLS mode for a gRPC channel.
    ///
    /// Defaults to [`Insecure`](GrpcTlsMode::Insecure) so existing deployments
    /// that omit the field keep their current plaintext behaviour unchanged.
    #[non_exhaustive]
    #[derive(Clone, Debug, Default, serde::Deserialize, PartialEq, Eq, Hash)]
    #[serde(rename_all = "lowercase")]
    pub enum GrpcTlsMode {
        /// Plaintext gRPC — default, backward-compatible.
        #[default]
        Insecure,
        /// TLS — `ca_cert_path` must also be set.
        Tls,
    }

    /// Build a tonic [`ClientTlsConfig`] from a PEM CA certificate file.
    ///
    /// Returns `None` when `mode` is `Insecure` (no TLS, no I/O performed).
    ///
    /// # Errors
    ///
    /// Returns an error when `mode` is `Tls` and:
    /// - `ca_cert_path` is `None`, or
    /// - the certificate file cannot be read.
    pub async fn build_grpc_client_tls_config(
        mode: &GrpcTlsMode,
        ca_cert_path: Option<&Path>,
    ) -> Result<Option<ClientTlsConfig>> {
        match mode {
            GrpcTlsMode::Insecure => Ok(None),
            GrpcTlsMode::Tls => {
                let path = ca_cert_path.ok_or_else(|| {
                    anyhow::anyhow!("ca_cert_path is required when tls_mode = \"tls\"")
                })?;
                let pem = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("read gRPC CA cert {}", path.display()))?;
                Ok(Some(
                    ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&pem)),
                ))
            }
        }
    }

    /// Build a tonic [`ServerTlsConfig`] from PEM certificate and key files.
    ///
    /// Returns `None` when both paths are absent — server starts without TLS,
    /// identical to the pre-TLS default behaviour.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - exactly one of `cert_path` / `key_path` is provided (both required together), or
    /// - either file cannot be read.
    pub async fn build_grpc_server_tls_config(
        cert_path: Option<&Path>,
        key_path: Option<&Path>,
    ) -> Result<Option<ServerTlsConfig>> {
        match (cert_path, key_path) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => {
                let cert_pem = tokio::fs::read(cert)
                    .await
                    .with_context(|| format!("read gRPC TLS cert {}", cert.display()))?;
                let key_pem = tokio::fs::read(key)
                    .await
                    .with_context(|| format!("read gRPC TLS key {}", key.display()))?;
                let identity = Identity::from_pem(cert_pem, key_pem);
                Ok(Some(ServerTlsConfig::new().identity(identity)))
            }
            _ => anyhow::bail!("cert_path and key_path must both be provided, or both omitted"),
        }
    }
}
