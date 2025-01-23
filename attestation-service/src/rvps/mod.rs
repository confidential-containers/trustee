// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use log::info;
pub use reference_value_provider_service::config::Config as RvpsCrateConfig;
use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

#[cfg(feature = "rvps-grpc")]
pub mod grpc;

pub mod builtin;

#[derive(Error, Debug)]
pub enum RvpsError {
    #[error("Serde Json Error: {0}")]
    SerdeJson(#[from] serde_json::Error),

    #[cfg(feature = "rvps-grpc")]
    #[error("Returned status: {0}")]
    Status(#[from] tonic::Status),

    #[cfg(feature = "rvps-grpc")]
    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

type Result<T> = std::result::Result<T, RvpsError>;

/// The interfaces of Reference Value Provider Service
/// * `verify_and_extract` is responsible for verify a message and
/// store reference values from it.
/// * `get_digests` gets trusted digests by the artifact's name.
#[async_trait::async_trait]
pub trait RvpsApi {
    /// Verify the given message and register the reference value included.
    async fn verify_and_extract(&mut self, message: &str) -> Result<()>;

    /// Get the reference values / golden values / expected digests in hex.
    async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum RvpsConfig {
    BuiltIn(RvpsCrateConfig),
    #[cfg(feature = "rvps-grpc")]
    GrpcRemote(grpc::RvpsRemoteConfig),
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self::BuiltIn(RvpsCrateConfig::default())
    }
}

pub async fn initialize_rvps_client(config: &RvpsConfig) -> Result<Box<dyn RvpsApi + Send + Sync>> {
    match config {
        RvpsConfig::BuiltIn(config) => {
            info!("launch a built-in RVPS.");
            Ok(Box::new(builtin::BuiltinRvps::new(config.clone())?)
                as Box<dyn RvpsApi + Send + Sync>)
        }
        #[cfg(feature = "rvps-grpc")]
        RvpsConfig::GrpcRemote(config) => {
            info!("connect to remote RVPS: {}", config.address);
            Ok(Box::new(grpc::Agent::new(&config.address).await?)
                as Box<dyn RvpsApi + Send + Sync>)
        }
    }
}
