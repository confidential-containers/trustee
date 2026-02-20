// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0
//

use actix_web::http::Method;
use anyhow::{Context, Result};
use async_trait::async_trait;
use log::info;
use mobc::{Manager, Pool};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::plugins::external::plugin_api::{
    kbs_plugin_client::KbsPluginClient, GetCapabilitiesRequest, PluginRequest,
};
use crate::plugins::plugin_manager::{ClientPlugin, ExternalPluginConfig, TlsMode};

const DEFAULT_POOL_SIZE: u64 = 100;

pub struct GrpcPluginProxy {
    pool: Pool<PluginGrpcManager>,
    timeout: Option<Duration>,
    config: ExternalPluginConfig,
}

impl GrpcPluginProxy {
    pub async fn new(config: ExternalPluginConfig) -> Result<Self> {
        let manager = PluginGrpcManager {
            endpoint: config.endpoint.clone(),
            tls_mode: config.tls_mode.clone(),
            ca_cert_path: config.ca_cert_path.clone(),
            client_cert_path: config.client_cert_path.clone(),
            client_key_path: config.client_key_path.clone(),
        };
        let pool = Pool::builder().max_open(DEFAULT_POOL_SIZE).build(manager);

        // Get capabilities at startup (per Phase 1 decision)
        let mut client = pool
            .get()
            .await
            .context("Failed to connect to external plugin")?;

        let caps_request = tonic::Request::new(GetCapabilitiesRequest {});
        let caps_response = client
            .get_capabilities(caps_request)
            .await
            .context("Failed to get plugin capabilities")?
            .into_inner();

        // Log capabilities at info level (per Phase 1 decision)
        info!(
            "Connected to external plugin '{}' (version {}, endpoint {})",
            caps_response.name, caps_response.version, config.endpoint
        );

        if !caps_response.supported_methods.is_empty() {
            info!(
                "Plugin '{}' supports HTTP methods: {:?}",
                caps_response.name, caps_response.supported_methods
            );
        }

        let timeout = config.timeout_ms.map(Duration::from_millis);

        Ok(Self {
            pool,
            timeout,
            config,
        })
    }
}

pub struct PluginGrpcManager {
    endpoint: String,
    tls_mode: TlsMode,
    ca_cert_path: Option<PathBuf>,
    client_cert_path: Option<PathBuf>,
    client_key_path: Option<PathBuf>,
}

#[async_trait]
impl Manager for PluginGrpcManager {
    type Connection = KbsPluginClient<Channel>;
    type Error = anyhow::Error;

    async fn connect(&self) -> Result<Self::Connection> {
        let mut channel = Channel::from_shared(self.endpoint.clone())?;

        match &self.tls_mode {
            TlsMode::Mtls => {
                let ca_cert = std::fs::read(
                    self.ca_cert_path
                        .as_ref()
                        .context("ca_cert_path required for mTLS")?,
                )?;
                let client_cert = std::fs::read(
                    self.client_cert_path
                        .as_ref()
                        .context("client_cert_path required for mTLS")?,
                )?;
                let client_key = std::fs::read(
                    self.client_key_path
                        .as_ref()
                        .context("client_key_path required for mTLS")?,
                )?;

                let tls_config = ClientTlsConfig::new()
                    .ca_certificate(Certificate::from_pem(&ca_cert))
                    .identity(Identity::from_pem(&client_cert, &client_key));

                channel = channel.tls_config(tls_config)?;
            }
            TlsMode::Tls => {
                let ca_cert = std::fs::read(
                    self.ca_cert_path
                        .as_ref()
                        .context("ca_cert_path required for TLS")?,
                )?;

                let tls_config =
                    ClientTlsConfig::new().ca_certificate(Certificate::from_pem(&ca_cert));

                channel = channel.tls_config(tls_config)?;
            }
            TlsMode::Insecure => {
                // No TLS config, plaintext connection
            }
        }

        let connection = channel
            .connect()
            .await
            .context("Connect to plugin gRPC endpoint")?;

        Ok(KbsPluginClient::new(connection))
    }

    async fn check(&self, conn: Self::Connection) -> Result<Self::Connection> {
        Ok(conn)
    }
}

#[async_trait]
impl ClientPlugin for GrpcPluginProxy {
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        let mut client = self.pool.get().await?;

        let mut request = tonic::Request::new(PluginRequest {
            body: body.to_vec(),
            query: query.clone(),
            path: path.iter().map(|s| s.to_string()).collect(),
            method: method.to_string(),
        });

        if let Some(timeout) = self.timeout {
            request.set_timeout(timeout);
        }

        let response = client.handle(request).await.map_err(map_grpc_error)?;

        Ok(response.into_inner().body)
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        // Return config value directly (no gRPC call per Phase 1 decision)
        Ok(self.config.validate_auth)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        // Return config value directly (no gRPC call per Phase 1 decision)
        Ok(self.config.encrypted)
    }
}

/// Map tonic::Status codes to anyhow errors with context.
///
/// Note: KBS error.rs currently only distinguishes 404 NotFound and 401 Unauthorized.
/// All plugin errors are wrapped in Error::PluginInternalError which returns 401.
/// We provide detailed error messages for debugging even though HTTP status is simplified.
fn map_grpc_error(status: tonic::Status) -> anyhow::Error {
    use tonic::Code;

    match status.code() {
        Code::NotFound => {
            anyhow::anyhow!("Plugin resource not found: {}", status.message())
        }
        Code::Unavailable | Code::DeadlineExceeded => {
            anyhow::anyhow!("Plugin service unavailable: {}", status.message())
        }
        Code::InvalidArgument => {
            anyhow::anyhow!("Invalid request to plugin: {}", status.message())
        }
        Code::PermissionDenied | Code::Unauthenticated => {
            anyhow::anyhow!("Plugin access denied: {}", status.message())
        }
        Code::Unimplemented => {
            anyhow::anyhow!("Plugin operation not implemented: {}", status.message())
        }
        _ => {
            anyhow::anyhow!(
                "Plugin gRPC error ({}): {}",
                status.code(),
                status.message()
            )
        }
    }
}
