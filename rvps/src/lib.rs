// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod client;
pub mod config;
pub mod extractors;
pub mod reference_value;
pub mod rvps_api;
pub mod server;
pub mod storage;

pub use config::Config;
pub use reference_value::{ReferenceValue, TrustedDigest};
pub use storage::ReferenceValueStorage;

use extractors::Extractors;

pub use serde_json::Value;

use anyhow::{bail, Context, Result};
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default version of Message
static MESSAGE_VERSION: &str = "0.1.0";

/// Message is an overall packet that Reference Value Provider Service
/// receives. It will contain payload (content of different provenance,
/// JSON format), provenance type (indicates the type of the payload)
/// and a version number (use to distinguish different version of
/// message, for extendability).
/// * `version`: version of this message.
/// * `payload`: content of the provenance, JSON encoded.
/// * `type`: provenance type of the payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(default = "default_version")]
    version: String,
    payload: String,
    r#type: String,
}

/// Set the default version for Message
fn default_version() -> String {
    MESSAGE_VERSION.into()
}

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Rvps {
    extractors: Extractors,
    storage: Box<dyn ReferenceValueStorage + Send + Sync>,
}

impl Rvps {
    /// Instantiate a new RVPS
    pub fn new(config: Config) -> Result<Self> {
        let extractors = Extractors::default();
        let storage = config.storage.to_storage()?;

        Ok(Rvps {
            extractors,
            storage,
        })
    }

    pub fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let message: Message = serde_json::from_str(message).context("parse message")?;

        // Judge the version field
        if message.version != MESSAGE_VERSION {
            bail!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            );
        }

        let rv = self.extractors.process(message)?;
        for v in rv.iter() {
            let old = self.storage.set(v.name().to_string(), v.clone())?;
            if let Some(old) = old {
                info!("Old Reference value of {} is replaced.", old.name());
            }
        }

        Ok(())
    }

    pub fn get_digest(&self, id: String) -> Result<Value> {
        if let Some(rv) = self.storage.get(id.clone())? {
            return Ok(rv.value);
        }
        bail!("Reference Value {id} not found.")
    }

    pub fn get_digests(&self) -> Result<HashMap<String, Value>> {
        let mut rv_map = HashMap::new();
        let reference_values = self.storage.get_values()?;

        for rv in reference_values {
            if rv.expired() {
                warn!("Reference value of {} is expired.", rv.name());
                continue;
            }

            rv_map.insert(rv.name().to_string(), rv.value());
        }
        Ok(rv_map)
    }
}
