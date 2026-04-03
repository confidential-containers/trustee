// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use tracing::{info, warn};

use crate::config::HttpServerConfig;

/// PQC algorithm candidates in priority order
/// Based on OpenSSL 3.5+ supported hybrid groups
const PQC_CANDIDATES: &[&str] = &[
    "X25519MLKEM768",     // X25519 + ML-KEM-768 (preferred)
    "SecP256r1MLKEM768",  // NIST P-256 + ML-KEM-768 (FIPS)
    "X448MLKEM1024",      // X448 + ML-KEM-1024 (high security)
    "SecP384r1MLKEM1024", // NIST P-384 + ML-KEM-1024 (FIPS + high security)
];

/// Classical algorithm groups for fallback
const CLASSICAL_GROUPS: &str = "X25519:secp256r1:secp384r1";

/// Global cache for the best supported PQC group
static BEST_PQC_GROUP: OnceLock<Option<&'static str>> = OnceLock::new();

/// Detect the best PQC group supported by OpenSSL
///
/// Tries each candidate in priority order and returns the first one supported.
/// The result is cached globally for performance.
///
/// Returns:
/// - Some(algorithm) if PQC is supported
/// - None if no PQC algorithms are available
fn detect_best_pqc_group() -> Option<&'static str> {
    *BEST_PQC_GROUP.get_or_init(|| {
        use openssl::ssl::{SslAcceptor, SslMethod};

        // Create a temporary acceptor for testing
        let mut builder = match SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to create SSL acceptor for PQC detection: {}", e);
                return None;
            }
        };

        // Try each PQC candidate in priority order
        for &candidate in PQC_CANDIDATES {
            if builder.set_groups_list(candidate).is_ok() {
                info!("PQC algorithm detected: {}", candidate);
                return Some(candidate);
            }
        }

        info!(
            "No PQC algorithms supported by OpenSSL (tried: {:?})",
            PQC_CANDIDATES
        );
        None
    })
}

pub fn tls_config(config: &HttpServerConfig) -> Result<openssl::ssl::SslAcceptorBuilder> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let cert_file = config
        .certificate
        .as_ref()
        .ok_or_else(|| anyhow!("Missing certificate"))?;

    let key_file = config
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("Missing private key"))?;

    // Use mozilla_intermediate_v5 which supports both TLS 1.2 and TLS 1.3
    // Note: mozilla_intermediate (v4) explicitly disables TLS 1.3 via NO_TLSV1_3 flag
    // Version 5 is required for TLS 1.3 and PQC support
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(cert_file)?;

    // Auto-detect and configure TLS groups based on OpenSSL capabilities
    let groups = if let Some(pqc_group) = detect_best_pqc_group() {
        info!("PQC TLS enabled with {}", pqc_group);
        format!("{}:{}", pqc_group, CLASSICAL_GROUPS)
    } else {
        info!(
            "PQC TLS not available, using classical algorithms: {}",
            CLASSICAL_GROUPS
        );
        CLASSICAL_GROUPS.to_string()
    };

    builder.set_groups_list(&groups)?;
    info!("KBS TLS groups: {}", groups);
    info!("Supported TLS versions: 1.2, 1.3");

    Ok(builder)
}
