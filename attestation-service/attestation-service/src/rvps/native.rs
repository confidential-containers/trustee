// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use chrono::{DateTime, Utc};
use log::{info, warn};
use std::time::SystemTime;

use super::{
    extractors::{Extractors, ExtractorsImpl},
    pre_processor::{PreProcessor, PreProcessorAPI, Ware},
    Message, Store, TrustedDigest, MESSAGE_VERSION, RVPSAPI,
};

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

#[async_trait::async_trait]
impl RVPSAPI for Core {
    async fn verify_and_extract(&mut self, mut message: Message) -> Result<()> {
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

    async fn get_digests(&self, name: &str) -> Result<Option<TrustedDigest>> {
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
