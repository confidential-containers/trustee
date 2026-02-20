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
use std::time::Duration;
use tonic::transport::Channel;

use crate::plugins::external::plugin_api::{
    kbs_plugin_client::KbsPluginClient, GetCapabilitiesRequest, PluginRequest,
};
use crate::plugins::plugin_manager::{ClientPlugin, ExternalPluginConfig};

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
}

#[async_trait]
impl Manager for PluginGrpcManager {
    type Connection = KbsPluginClient<Channel>;
    type Error = anyhow::Error;

    async fn connect(&self) -> Result<Self::Connection> {
        let channel = Channel::from_shared(self.endpoint.clone())?
            .connect()
            .await?;
        Ok(KbsPluginClient::new(channel))
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
