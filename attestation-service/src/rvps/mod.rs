// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
pub use reference_value_provider_service::config::Config as RvpsCrateConfig;
use reference_value_provider_service::extractors::ExtractorsConfig;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{info, instrument};

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

    /// Get the reference value by the given id.
    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type")]
pub enum RvpsConfig {
    BuiltIn {
        extractors: Option<ExtractorsConfig>,
    },
    #[cfg(feature = "rvps-grpc")]
    GrpcRemote(grpc::RvpsRemoteConfig),
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self::BuiltIn { extractors: None }
    }
}

pub type RvpsClient = Arc<Mutex<dyn RvpsApi + Send + Sync>>;

#[instrument(skip_all, name = "Initialize RVPS")]
pub async fn initialize_rvps_client(
    config: &RvpsConfig,
    storage_type: KeyValueStorageType,
    storage_config: &KeyValueStorageStructConfig,
) -> Result<RvpsClient> {
    match config {
        RvpsConfig::BuiltIn { extractors } => {
            info!("launch a built-in RVPS.");
            Ok(Arc::new(Mutex::new(
                builtin::BuiltinRvps::new(extractors.clone(), storage_type, storage_config).await?,
            )) as RvpsClient)
        }
        #[cfg(feature = "rvps-grpc")]
        RvpsConfig::GrpcRemote(config) => {
            info!("connect to remote RVPS: {}", config.address);
            Ok(Arc::new(Mutex::new(grpc::Agent::new(&config.address).await?)) as RvpsClient)
        }
    }
}
