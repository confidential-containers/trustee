// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

// Add your specific provenance declaration here.

use anyhow::*;
use std::collections::HashMap;

use crate::ReferenceValue;

#[cfg(feature = "in-toto")]
pub mod in_toto;

pub mod sample;
pub mod swid;

/// Extractor is a standard interface that all provenance extractors
/// need to implement. Here reference_value can be modified in the
/// handler, added any field if needed.
pub trait Extractor {
    fn verify_and_extract(&self, provenance: &str) -> Result<Vec<ReferenceValue>>;
}

pub type ExtractorInstance = Box<dyn Extractor + Sync + Send>;
type ExtractorInstantiateFunc = Box<dyn Fn() -> ExtractorInstance + Send + Sync>;

pub struct ExtractorModuleList {
    mod_list: HashMap<String, ExtractorInstantiateFunc>,
}

impl Default for ExtractorModuleList {
    fn default() -> ExtractorModuleList {
        // TODO: when new extractor is added, change mod_list
        // to mutable.
        let mut mod_list = HashMap::new();

        {
            let instantiate_func: ExtractorInstantiateFunc =
                Box::new(|| -> ExtractorInstance { Box::<sample::SampleExtractor>::default() });
            mod_list.insert("sample".to_string(), instantiate_func);
        }

        {
            let instantiate_func: ExtractorInstantiateFunc =
                Box::new(|| -> ExtractorInstance { Box::<swid::SwidExtractor>::default() });
            mod_list.insert("swid".to_string(), instantiate_func);
        }

        #[cfg(feature = "in-toto")]
        {
            let instantiate_func: ExtractorInstantiateFunc =
                Box::new(|| -> ExtractorInstance { Box::new(in_toto::InTotoExtractor::new()) });
            mod_list.insert("in-toto".to_string(), instantiate_func);
        }

        ExtractorModuleList { mod_list }
    }
}

impl ExtractorModuleList {
    pub fn get_func(&self, extractor_name: &str) -> Result<&ExtractorInstantiateFunc> {
        let instantiate_func: &ExtractorInstantiateFunc =
            self.mod_list.get(extractor_name).ok_or_else(|| {
                anyhow!(
                    "RVPS Extractors does not support the given extractor: {}!",
                    extractor_name
                )
            })?;
        Ok(instantiate_func)
    }
}
