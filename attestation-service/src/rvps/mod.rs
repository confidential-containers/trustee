// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use log::{info, warn};
pub use reference_value_provider_service::config::{
    Config as RvpsCrateConfig, DEFAULT_STORAGE_TYPE,
};
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;

/// The interfaces of Reference Value Provider Service
/// * `verify_and_extract` is responsible for verify a message and
/// store reference values from it.
/// * `get_digests` gets trusted digests by the artifact's name.
#[async_trait::async_trait]
pub trait RvpsApi {
    /// Verify the given message and register the reference value included.
    async fn verify_and_extract(&mut self, message: &str) -> Result<()>;

    /// Get the reference values / golden values / expected digests in hex of the
    /// given component name.
    async fn get_digests(&self, name: &str) -> Result<Vec<String>>;
}

#[cfg(feature = "rvps-grpc")]
pub mod grpc;

#[cfg(feature = "rvps-builtin")]
pub mod builtin;

fn default_store_type() -> String {
    DEFAULT_STORAGE_TYPE.into()
}

fn default_store_config() -> Value {
    json!({})
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct RvpsConfig {
    /// Address of remote RVPS. If this field is given, a remote RVPS will be connected to.
    /// If this field is not given, a built-in RVPS will be used.
    #[serde(default = "String::default")]
    pub remote_addr: String,

    /// This field will be used only if `remote_addr` is not given.
    #[serde(default = "default_store_type")]
    pub store_type: String,

    /// This field will be used only if `remote_addr` is not given.
    #[serde(default = "default_store_config")]
    pub store_config: Value,
}

impl From<RvpsConfig> for RvpsCrateConfig {
    fn from(val: RvpsConfig) -> RvpsCrateConfig {
        RvpsCrateConfig {
            store_type: val.store_type,
            store_config: val.store_config,
        }
    }
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self {
            remote_addr: String::new(),
            store_type: default_store_type(),
            store_config: default_store_config(),
        }
    }
}

#[derive(Error, Debug)]
pub enum RvpsError {
    #[error("feature `rvps-grpc` or `rvps-builtin` should be enabled")]
    FeatureNotEnabled,
    #[error("Serde Json Error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Returned status: {0}")]
    Status(#[from] tonic::Status),
    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub async fn initialize_rvps_client(
    config: &RvpsConfig,
) -> Result<Box<dyn RvpsApi + Send + Sync>, RvpsError> {
    cfg_if::cfg_if! {
        if #[cfg(feature = "rvps-grpc")] {
            if !config.remote_addr.is_empty() {
                let remote_addr = &config.remote_addr;
                info!("connect to remote RVPS: {remote_addr}");
                Ok(Box::new(grpc::Agent::new(remote_addr).await?) as Box<dyn RvpsApi + Send + Sync>)
            } else {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "rvps-builtin")] {
                        warn!("No RVPS address provided and will launch a built-in rvps");
                        Ok(Box::new(builtin::Rvps::new(config.clone().into())?) as Box<dyn RvpsApi + Send + Sync>)
                    } else {
                        return RvpsError::FeatureNotEnabled;
                    }
                }
            }
        } else if #[cfg(feature = "rvps-builtin")] {
            info!("launch a built-in RVPS.");
            Ok(Box::new(builtin::Rvps::new(config.clone().into())) as Box<dyn RvpsApi + Send + Sync>)
        } else {
            return RvpsError::FeatureNotEnabled;
        }
    }
}
