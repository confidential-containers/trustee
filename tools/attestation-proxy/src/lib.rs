// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

mod attestation;
mod config;
mod error;
mod proxy;

use std::path::Path;

use anyhow::{Context, Result};
use pingora::prelude::Server;

use crate::attestation::AttestationVerifier;
use crate::config::ProxyConfig;
use crate::proxy::AttestationProxy;

/// Build the configured Pingora server before entering its runtime.
pub fn build_server(path: &Path) -> Result<Server> {
    let config = ProxyConfig::load(path)?;
    // Pingora owns its runtimes and must start outside a Tokio runtime.
    let verifier = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("failed to initialize the token verifier runtime")?
        .block_on(AttestationVerifier::new(
            config.attestation.clone(),
            config.policy.clone(),
        ))?;
    let upstream = config.resolve_upstream()?;
    let proxy = AttestationProxy::new(
        verifier,
        upstream,
        config.max_token_bytes,
        config.upstream_timeout(),
    );

    let mut server = Server::new(None).context("failed to initialize Pingora")?;
    server.bootstrap();

    let mut service = pingora::proxy::http_proxy_service(&server.configuration, proxy);
    if let Some(tls) = &config.tls {
        tracing::info!(address = %config.listen_address, "starting HTTPS attestation proxy");
        service
            .add_tls(
                &config.listen_address,
                path_to_str(&tls.certificate_path)?,
                path_to_str(&tls.private_key_path)?,
            )
            .context("failed to configure the Pingora TLS listener")?;
    } else {
        tracing::warn!(
            address = %config.listen_address,
            "starting without TLS; use only for local demonstrations or behind a TLS terminator"
        );
        service.add_tcp(&config.listen_address);
    }

    server.add_service(service);
    Ok(server)
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}
