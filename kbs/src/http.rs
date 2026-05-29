// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::OnceLock;

use anyhow::{anyhow, Result};
use tracing::{debug, info, warn};

use crate::config::{HttpServerConfig, TlsConfig, TlsProfile, TlsVersion};
use openssl::ssl::SslVersion;

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

/// Apply TLS profile-specific configuration
fn apply_mozilla_profile(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    profile: &TlsProfile,
) -> Result<()> {
    match profile {
        TlsProfile::Old => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
            info!("TLS profile: Old (minimum TLS 1.2)");
        }
        TlsProfile::Intermediate => {
            // Already configured by mozilla_intermediate_v5
            info!("TLS profile: Intermediate (TLS 1.2+, recommended)");
        }
        TlsProfile::Modern => {
            builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
            info!("TLS profile: Modern (TLS 1.3 only)");
        }
        TlsProfile::Custom => {
            info!("TLS profile: Custom");
        }
    }
    Ok(())
}

/// Apply custom TLS configuration from explicit fields
fn apply_custom_tls_config(
    builder: &mut openssl::ssl::SslAcceptorBuilder,
    config: &TlsConfig,
) -> Result<()> {
    if let Some(min_version) = &config.min_version {
        let ssl_version = match min_version {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            TlsVersion::Tls13 => SslVersion::TLS1_3,
        };
        builder.set_min_proto_version(Some(ssl_version))?;
        debug!("TLS minimum version: {:?}", min_version);
    }

    if let Some(max_version) = &config.max_version {
        let ssl_version = match max_version {
            TlsVersion::Tls12 => SslVersion::TLS1_2,
            TlsVersion::Tls13 => SslVersion::TLS1_3,
        };
        builder.set_max_proto_version(Some(ssl_version))?;
        debug!("TLS maximum version: {:?}", max_version);
    }

    if let Some(ciphers) = &config.ciphers {
        // set_cipher_list() configures TLS 1.2 ciphers
        // set_ciphersuites() configures TLS 1.3 ciphers
        // TLS 1.2 is disabled if: min_version is 1.3 OR profile is Modern
        // TLS 1.3 is disabled if: max_version is 1.2
        let tls12_disabled =
            config.min_version == Some(TlsVersion::Tls13) || config.profile == TlsProfile::Modern;
        let tls13_disabled = config.max_version == Some(TlsVersion::Tls12);

        if !tls12_disabled {
            builder.set_cipher_list(ciphers)?;
        }
        if !tls13_disabled {
            builder.set_ciphersuites(ciphers)?;
        }
        debug!("TLS ciphers: {}", ciphers);
    }

    Ok(())
}

/// Determine effective TLS groups configuration
fn get_effective_groups(config: &TlsConfig) -> String {
    if let Some(groups) = &config.groups {
        return groups.clone();
    }

    if let Some(pqc_group) = detect_best_pqc_group() {
        format!("{}:{}", pqc_group, CLASSICAL_GROUPS)
    } else {
        CLASSICAL_GROUPS.to_string()
    }
}

pub fn tls_config(config: &HttpServerConfig) -> Result<openssl::ssl::SslAcceptorBuilder> {
    use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

    let cert_file = config
        .tls
        .certificate
        .as_ref()
        .ok_or_else(|| anyhow!("Missing certificate"))?;

    let key_file = config
        .tls
        .private_key
        .as_ref()
        .ok_or_else(|| anyhow!("Missing private key"))?;

    // Use mozilla_intermediate_v5 which supports both TLS 1.2 and TLS 1.3
    // Note: mozilla_intermediate (v4) explicitly disables TLS 1.3 via NO_TLSV1_3 flag
    // Version 5 is required for TLS 1.3 and PQC support
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(cert_file)?;

    // Apply profile-specific configuration
    apply_mozilla_profile(&mut builder, &config.tls.profile)?;

    // Apply custom overrides (these take precedence)
    if config.tls.profile == TlsProfile::Custom
        || config.tls.min_version.is_some()
        || config.tls.max_version.is_some()
        || config.tls.ciphers.is_some()
    {
        apply_custom_tls_config(&mut builder, &config.tls)?;
    }

    // Configure TLS groups (with PQC auto-detection)
    let groups = get_effective_groups(&config.tls);
    builder.set_groups_list(&groups)?;

    if config.tls.groups.is_some() {
        info!("TLS groups (explicit): {}", groups);
    } else if groups.contains("MLKEM") {
        info!("TLS groups (auto-detected PQC): {}", groups);
    } else {
        info!("TLS groups (classical): {}", groups);
    }

    Ok(builder)
}
