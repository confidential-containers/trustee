// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0

//! TLS configuration helpers for plugin servers.
//!
//! Provides a type-safe [`TlsConfig`] enum that mirrors the KBS client-side
//! TlsMode pattern, offering mutual TLS and server-only TLS modes.
//!
//! # Example
//!
//! ```rust,no_run
//! use kbs_plugin_sdk::TlsConfig;
//!
//! // Mutual TLS (recommended for production)
//! let mtls = TlsConfig::mtls(
//!     "/etc/plugin/server.pem",
//!     "/etc/plugin/server.key",
//!     "/etc/plugin/client-ca.pem",
//! );
//!
//! // Server-only TLS
//! let tls = TlsConfig::tls("/etc/plugin/server.pem", "/etc/plugin/server.key");
//! ```

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};

/// TLS configuration mode for plugin servers.
///
/// Matches KBS client-side TlsMode for consistent configuration across
/// the KBS ecosystem. Plugins that need no TLS simply omit the `.tls()`
/// call on [`super::server::PluginServerBuilder`].
#[derive(Debug, Clone)]
pub enum TlsConfig {
    /// Mutual TLS: server and client authenticate with certificates.
    Mtls {
        /// Path to server certificate PEM file.
        server_cert: PathBuf,
        /// Path to server private key PEM file.
        server_key: PathBuf,
        /// Path to client CA certificate PEM file.
        client_ca: PathBuf,
    },
    /// Server-only TLS: server presents certificate, client verifies.
    Tls {
        /// Path to server certificate PEM file.
        server_cert: PathBuf,
        /// Path to server private key PEM file.
        server_key: PathBuf,
    },
}

impl TlsConfig {
    /// Create mutual TLS configuration from PEM file paths.
    ///
    /// Both the server and client authenticate with certificates.
    /// This is the recommended mode for production deployments.
    pub fn mtls(
        server_cert: impl Into<PathBuf>,
        server_key: impl Into<PathBuf>,
        client_ca: impl Into<PathBuf>,
    ) -> Self {
        TlsConfig::Mtls {
            server_cert: server_cert.into(),
            server_key: server_key.into(),
            client_ca: client_ca.into(),
        }
    }

    /// Create server-only TLS configuration from PEM file paths.
    ///
    /// The server presents its certificate; the client verifies it but
    /// does not authenticate with a certificate.
    pub fn tls(server_cert: impl Into<PathBuf>, server_key: impl Into<PathBuf>) -> Self {
        TlsConfig::Tls {
            server_cert: server_cert.into(),
            server_key: server_key.into(),
        }
    }

    /// Convert to tonic's [`ServerTlsConfig`].
    ///
    /// Reads PEM files from disk and validates they exist. Fails fast
    /// with descriptive error messages if files are missing or unreadable.
    pub(crate) fn into_server_tls_config(self) -> Result<ServerTlsConfig> {
        match self {
            TlsConfig::Mtls {
                server_cert,
                server_key,
                client_ca,
            } => {
                let cert = fs::read(&server_cert).with_context(|| {
                    format!("failed to read server cert: {}", server_cert.display())
                })?;
                let key = fs::read(&server_key).with_context(|| {
                    format!("failed to read server key: {}", server_key.display())
                })?;
                let ca = fs::read(&client_ca).with_context(|| {
                    format!("failed to read client CA: {}", client_ca.display())
                })?;

                Ok(ServerTlsConfig::new()
                    .identity(Identity::from_pem(&cert, &key))
                    .client_ca_root(Certificate::from_pem(&ca)))
            }
            TlsConfig::Tls {
                server_cert,
                server_key,
            } => {
                let cert = fs::read(&server_cert).with_context(|| {
                    format!("failed to read server cert: {}", server_cert.display())
                })?;
                let key = fs::read(&server_key).with_context(|| {
                    format!("failed to read server key: {}", server_key.display())
                })?;

                Ok(ServerTlsConfig::new().identity(Identity::from_pem(&cert, &key)))
            }
        }
    }
}
