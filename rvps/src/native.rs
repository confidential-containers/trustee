// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Context, Result};
use log::{info, warn};
use std::collections::HashMap;

use crate::{store::StoreType, Config};

use super::{
    extractors::{Extractors, ExtractorsImpl},
    pre_processor::{PreProcessor, PreProcessorAPI},
    Message, Store, MESSAGE_VERSION,
};

/// The core of the RVPS, s.t. componants except communication componants.
pub struct Core {
    pre_processor: PreProcessor,
    extractors: ExtractorsImpl,
    store: Box<dyn Store + Send + Sync>,
}

impl Core {
    /// Instantiate  a new RVPS Core
    pub fn new(config: Config) -> Result<Self> {
        let pre_processor = PreProcessor::default();

        let extractors = ExtractorsImpl::default();

        let store_type = StoreType::try_from(&config.store_type[..])?;
        let store = store_type.to_store(config.store_config)?;

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
            let old = self.store.set(v.name().to_string(), v.clone()).await?;
            if let Some(old) = old {
                info!("Old Reference value of {} is replaced.", old.name());
            }
        }

        Ok(())
    }

    pub async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
        let mut rv_map = HashMap::new();
        let reference_values = self.store.get_values().await?;

        for rv in reference_values {
            if rv.expired() {
                warn!("Reference value of {} is expired.", rv.name());
                continue;
            }

            let hash_values = rv
                .hash_values()
                .iter()
                .map(|pair| pair.value().to_owned())
                .collect();

            rv_map.insert(rv.name().to_string(), hash_values);
        }
        Ok(rv_map)
    }
}
