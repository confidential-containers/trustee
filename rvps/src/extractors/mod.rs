// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! Extractors for RVPS.

use anyhow::*;
use log::warn;
use serde::Deserialize;
use std::collections::HashMap;

use super::{Message, ReferenceValue};

pub mod sample;
pub mod swid;

#[cfg(feature = "in-toto")]
pub mod in_toto;

/// Extractor is a standard interface that all provenance extractors
/// need to implement. Here reference_value can be modified in the
/// handler, added any field if needed.
pub trait Extractor {
    fn verify_and_extract(&self, provenance: &str) -> Result<Vec<ReferenceValue>>;
}

pub type ExtractorInstance = Box<dyn Extractor + Sync + Send>;

pub struct Extractors {
    /// A map of provenance types to Extractor instances
    extractor_map: HashMap<String, ExtractorInstance>,
}

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ExtractorsConfig {
    swid_extractor: Option<swid::SwidExtractorConfig>,
}

impl Extractors {
    pub fn new(config: Option<ExtractorsConfig>) -> Result<Self> {
        let mut extractor_map: HashMap<String, ExtractorInstance> = HashMap::new();

        extractor_map.insert(
            "sample".to_string(),
            Box::new(sample::SampleExtractor::default()),
        );

        let swid_config = config.clone().map(|c| c.swid_extractor).unwrap_or(None);
        if config.is_none() {
            warn!("No configuration for SWID extractor provided. Default will be used.");
        }

        extractor_map.insert(
            "swid".to_string(),
            Box::new(swid::SwidExtractor::new(swid_config)?),
        );

        #[cfg(feature = "in-toto")]
        extractor_map.insert(
            "in-toto".to_string(),
            Box::new(in_toto::InTotoExtractor::new()),
        );

        Ok(Extractors { extractor_map })
    }

    /// Process the message, by verifying the provenance
    /// and extracting reference values within.
    /// If provenance is valid, return all of the relevant
    /// reference values.
    /// Each ReferenceValue digest is expected to be base64 encoded.
    pub fn process(&mut self, message: Message) -> Result<Vec<ReferenceValue>> {
        let extractor_type = message.r#type;

        if let Some(extractor) = self.extractor_map.get_mut(&extractor_type) {
            return extractor.verify_and_extract(&message.payload);
        }

        bail!("Could not find extractor for {extractor_type}");
    }
}
