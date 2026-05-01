// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::sync::Arc;

use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType, StorageBackendConfig};
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

    #[cfg(feature = "rvps-grpc")]
    #[error("gRPC pool error: {0}")]
    GrpcPool(#[from] mobc::Error<anyhow::Error>),

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

        /// Optional storage backend configuration for RVPS.
        /// If provided, overrides the unified storage_backend for RVPS storage.
        /// If None, falls back to the unified storage_backend.
        #[serde(default)]
        storage: Option<StorageBackendConfig>,
    },
    #[cfg(feature = "rvps-grpc")]
    GrpcRemote(grpc::RvpsRemoteConfig),
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self::BuiltIn {
            extractors: None,
            storage: None,
        }
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
        RvpsConfig::BuiltIn {
            extractors,
            storage,
        } => {
            info!("launch a built-in RVPS.");

            // Use RVPS-specific storage if provided, otherwise fall back to defaults
            let (actual_storage_type, actual_storage_config) = match storage {
                Some(rvps_storage) => {
                    info!(
                        "Using RVPS-specific storage configuration: {:?}",
                        rvps_storage.storage_type
                    );
                    (rvps_storage.storage_type, &rvps_storage.backends)
                }
                None => {
                    info!(
                        "Using unified storage configuration for RVPS: {:?}",
                        storage_type
                    );
                    (storage_type, storage_config)
                }
            };

            Ok(Arc::new(Mutex::new(
                builtin::BuiltinRvps::new(
                    extractors.clone(),
                    actual_storage_type,
                    actual_storage_config,
                )
                .await?,
            )) as RvpsClient)
        }
        #[cfg(feature = "rvps-grpc")]
        RvpsConfig::GrpcRemote(config) => {
            info!("connect to remote RVPS: {}", config.address);
            Ok(Arc::new(Mutex::new(grpc::Agent::new(&config.address).await?)) as RvpsClient)
        }
    }
}
