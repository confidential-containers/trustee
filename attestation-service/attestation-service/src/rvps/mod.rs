// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use log::{info, warn};
use serde::Deserialize;

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

#[derive(Clone, Debug, Deserialize)]
pub struct RvpsConfig {
    /// Specify the underlying storage type of RVPS, e.g.
    ///
    /// - `localfs`: store inside local filesystem.
    /// - `localjson`: store inside local json file.
    ///
    /// Only used when feature `rvps-builtin` is enabled
    #[serde(default = "String::default")]
    pub store_type: String,

    /// The address of the remote RVPS server, e.g.
    ///
    /// - `http://127.0.0.1:50002`
    ///
    /// Only used when feature `rvps-rpc` is enabled
    #[serde(default = "String::default")]
    pub remote_addr: String,
}

impl Default for RvpsConfig {
    fn default() -> Self {
        Self {
            store_type: "LocalFs".into(),
            remote_addr: Default::default(),
        }
    }
}

impl RvpsConfig {
    /// If remote addr is specified and the feature `rvps-grpc` is enabled when
    /// built, will try to connect the remote rvps. Or, will use a built-in rvps.
    pub async fn to_rvps(&self) -> Result<Box<dyn RvpsApi + Send + Sync>> {
        cfg_if::cfg_if! {
            if #[cfg(feature = "rvps-grpc")] {
                if !self.remote_addr.is_empty() {
                    info!("connect to remote RVPS: {}", self.remote_addr);
                    Ok(Box::new(grpc::Agent::new(&self.remote_addr).await?) as Box<dyn RvpsApi + Send + Sync>)
                } else {
                    cfg_if::cfg_if! {
                        if #[cfg(feature = "rvps-builtin")] {
                            warn!("No RVPS address provided and will launch a built-in rvps");
                            Ok(Box::new(builtin::Rvps::new(&self.store_type)?) as Box<dyn RvpsApi + Send + Sync>)
                        } else {
                            Err(anyhow!("either feature `rvps-grpc` or `rvps-builtin` should be enabled."))
                        }
                    }
                }
            } else if #[cfg(feature = "rvps-builtin")] {
                info!("launch a built-in RVPS.");
                Ok(Box::new(builtin::Rvps::new(&self.store_type)) as Box<dyn RvpsApi + Send + Sync>)
            } else {
                Err(anyhow!("either feature `rvps-grpc` or `rvps-builtin` should be enabled."))
            }
        }
    }
}
