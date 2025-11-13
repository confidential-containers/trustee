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

use std::sync::Arc;

pub use config::Config;
use key_value_storage::{KeyValueStorage, SetParameters};
pub use reference_value::{ReferenceValue, TrustedDigest};

use extractors::Extractors;

pub use serde_json::Value;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

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
    storage: Arc<dyn KeyValueStorage>,
}

impl Rvps {
    /// Instantiate a new RVPS
    pub async fn new(config: Config) -> Result<Self> {
        let extractors = Extractors::new(config.extractors)?;
        let storage = config.storage.to_key_value_storage().await?;

        Ok(Rvps {
            extractors,
            storage,
        })
    }

    pub async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
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
            let value_bytes = v.to_bytes()?;
            self.storage
                .set(v.name(), &value_bytes, SetParameters { overwrite: true })
                .await?;
        }

        Ok(())
    }

    pub async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let reference_value_vec = self.storage.get(reference_value_id).await?;
        let Some(reference_value_vec) = reference_value_vec else {
            return Ok(None);
        };
        let reference_value: ReferenceValue =
            serde_json::from_slice(&reference_value_vec).context("deserialize reference value")?;

        Ok(Some(reference_value.value()))
    }
}
