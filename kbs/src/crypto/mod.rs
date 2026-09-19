// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod jwk;
pub(crate) mod jwt;

#[cfg(test)]
pub(crate) mod test_util {
    use std::net::SocketAddr;

    /// Bind a listener that completes the TCP handshake but never sends a byte,
    /// so a client without a timeout would wait on the TLS handshake forever.
    pub(crate) async fn silent_endpoint() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind silent listener");
        let addr = listener.local_addr().expect("silent listener address");
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }
}
