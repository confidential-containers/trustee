// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate strum;

#[macro_use]
extern crate strum_macros;

#[allow(clippy::new_without_default)]
pub mod extractors;
pub mod pre_processor;
pub mod reference_value;
pub mod store;

use std::time::SystemTime;

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use extractors::{Extractors, ExtractorsImpl};
use log::{info, warn};
use pre_processor::{PreProcessor, PreProcessorAPI, Ware};
use serde::{Deserialize, Serialize};

pub use reference_value::{ReferenceValue, TrustedDigest};
pub use store::Store;

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

/// The interfaces of Reference Value Provider Service
/// * `verify_and_extract` is responsible for verify a message and
/// store reference values from it.
/// * `get_digests` gets trusted digests by the artifact's name.
pub trait RVPSAPI {
    fn verify_and_extract(&mut self, message: Message) -> Result<()>;
    fn get_digests(&self, name: &str) -> Result<Option<TrustedDigest>>;
}

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Core {
    pre_processor: PreProcessor,
    extractors: ExtractorsImpl,
    store: Box<dyn Store + Send + Sync>,
}

impl Core {
    /// Instantiate  a new RVPS Core
    pub fn new(store: Box<dyn Store + Send + Sync>) -> Self {
        let pre_processor = PreProcessor::default();

        let extractors = ExtractorsImpl::default();

        Core {
            pre_processor,
            extractors,
            store,
        }
    }

    /// Add Ware to the Core's Pre-Processor
    pub fn with_ware(&mut self, ware: Box<dyn Ware + Send + Sync>) -> &Self {
        self.pre_processor.add_ware(ware);
        self
    }
}

impl RVPSAPI for Core {
    fn verify_and_extract(&mut self, mut message: Message) -> Result<()> {
        // Judge the version field
        if message.version != MESSAGE_VERSION {
            return Err(anyhow!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            ));
        }

        self.pre_processor.process(&mut message)?;

        let rv = self.extractors.process(message)?;
        for v in rv.iter() {
            let old = self.store.set(v.name().to_string(), v.clone())?;
            if let Some(old) = old {
                info!("Old Reference value of {} is replaced.", old.name());
            }
        }

        Ok(())
    }

    fn get_digests(&self, name: &str) -> Result<Option<TrustedDigest>> {
        let rv = self.store.get(name)?;
        match rv {
            None => Ok(None),
            Some(rv) => {
                let now: DateTime<Utc> = DateTime::from(SystemTime::now());
                if now > *rv.expired() {
                    warn!("Reference value of {} is expired.", name);
                    return Ok(None);
                }

                let hash_values = rv
                    .hash_values()
                    .iter()
                    .map(|pair| pair.value().to_owned())
                    .collect();

                Ok(Some(TrustedDigest {
                    name: name.to_owned(),
                    hash_values,
                }))
            }
        }
    }
}
