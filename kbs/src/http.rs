// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use crate::config::HttpServerConfig;

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

    let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
    builder.set_private_key_file(key_file, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(cert_file)?;

    Ok(builder)
}
