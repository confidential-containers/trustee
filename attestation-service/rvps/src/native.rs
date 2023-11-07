// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use log::{info, warn};
use std::time::SystemTime;

use crate::store::StoreType;

use super::{
    extractors::{Extractors, ExtractorsImpl},
    pre_processor::{PreProcessor, PreProcessorAPI},
    Message, Store, TrustedDigest, MESSAGE_VERSION,
};

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Core {
    pre_processor: PreProcessor,
    extractors: ExtractorsImpl,
    store: Box<dyn Store + Send + Sync>,
}

impl Core {
    /// Instantiate  a new RVPS Core
    pub fn new(store_type: &str) -> Result<Self> {
        let pre_processor = PreProcessor::default();

        let extractors = ExtractorsImpl::default();

        let store_type = StoreType::try_from(store_type)?;
        let store = store_type.to_store()?;

        Ok(Core {
            pre_processor,
            extractors,
            store,
        })
    }

    /// Add Ware to the Core's Pre-Processor
    pub fn with_ware(&mut self, _ware: &str) -> &Self {
        // TODO: no wares implemented now.
        self
    }

    pub async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let mut message: Message = serde_json::from_str(message).context("parse message")?;

        // Judge the version field
        if message.version != MESSAGE_VERSION {
            bail!(
                "Version unmatched! Need {}, given {}.",
                MESSAGE_VERSION,
                message.version
            );
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

    pub async fn get_digests(&self, name: &str) -> Result<Option<TrustedDigest>> {
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
