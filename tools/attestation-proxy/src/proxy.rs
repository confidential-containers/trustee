// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use pingora::http::RequestHeader;
use pingora::prelude::{HttpPeer, ProxyHttp, Result, Session};
use tracing::{debug, warn};

use crate::attestation::AttestationVerifier;
use crate::config::Upstream;

pub struct AttestationProxy {
    verifier: AttestationVerifier,
    upstream: Upstream,
    max_token_bytes: usize,
    upstream_timeout: Duration,
}

impl AttestationProxy {
    pub fn new(
        verifier: AttestationVerifier,
        upstream: Upstream,
        max_token_bytes: usize,
        upstream_timeout: Duration,
    ) -> Self {
        Self {
            verifier,
            upstream,
            max_token_bytes,
            upstream_timeout,
        }
    }
}

#[async_trait]
impl ProxyHttp for AttestationProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool> {
        let request = session.req_header();
        let method = request.method.as_str().to_owned();
        let path = request.uri.path().to_owned();

        if method == "GET" && path == "/healthz" {
            session
                .respond_error_with_body(200, Bytes::from_static(b"ok\n"))
                .await?;
            return Ok(true);
        }

        if !matches!(method.as_str(), "GET" | "HEAD") {
            return respond(session, 405, b"method not allowed\n").await;
        }

        let token = match bearer_token(request, self.max_token_bytes) {
            Ok(token) => token.to_owned(),
            Err(reason) => {
                warn!(reason, "request denied before attestation verification");
                return respond(session, 401, b"unauthorized\n").await;
            }
        };

        if let Err(error) = self.verifier.verify(&token).await {
            warn!(reason = %error, "request denied by attestation verification");
            let body: &'static [u8] = match error.status_code() {
                401 => b"unauthorized\n",
                403 => b"forbidden\n",
                _ => b"authorization unavailable\n",
            };
            return respond(session, error.status_code(), body).await;
        }

        debug!(method, path, "forwarding authorized request");
        Ok(false)
    }

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let mut peer = HttpPeer::new(
            self.upstream.address,
            self.upstream.tls,
            self.upstream.sni.clone(),
        );
        peer.options.connection_timeout = Some(self.upstream_timeout);
        peer.options.total_connection_timeout = Some(self.upstream_timeout);
        peer.options.read_timeout = Some(self.upstream_timeout);
        peer.options.write_timeout = Some(self.upstream_timeout);
        Ok(Box::new(peer))
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()> {
        for name in [
            "authorization",
            "host",
            "proxy-authorization",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
        ] {
            upstream_request.remove_header(name);
        }

        let attestation_headers: Vec<_> = upstream_request
            .headers
            .keys()
            .filter(|name| {
                let name = name.as_str();
                name.starts_with("attestation-")
                    || name.starts_with("x-attestation-")
                    || name.starts_with("x-attested-")
            })
            .cloned()
            .collect();
        for name in attestation_headers {
            upstream_request.remove_header(&name);
        }

        upstream_request.insert_header("host", self.upstream.host_header.as_str())?;
        Ok(())
    }
}

fn bearer_token(
    request: &RequestHeader,
    max_token_bytes: usize,
) -> std::result::Result<&str, &'static str> {
    let mut values = request.headers.get_all("authorization").iter();
    let value = values.next().ok_or("authorization header is missing")?;
    if values.next().is_some() {
        return Err("multiple authorization headers were supplied");
    }
    let value = value
        .to_str()
        .map_err(|_| "authorization header is not valid text")?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or("authorization header is not a bearer token")?;
    if token.len() > max_token_bytes {
        return Err("attestation token exceeds the configured size limit");
    }
    Ok(token)
}

async fn respond(session: &mut Session, status: u16, body: &'static [u8]) -> Result<bool> {
    session
        .respond_error_with_body(status, Bytes::from_static(body))
        .await?;
    Ok(true)
}
