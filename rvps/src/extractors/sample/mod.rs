// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a very simple format of provenance

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::ReferenceValue;

use super::Extractor;

#[derive(Serialize, Deserialize)]
pub struct Provenance {
    #[serde(flatten)]
    rvs: HashMap<String, serde_json::Value>,
}

#[derive(Default)]
pub struct SampleExtractor;

impl Extractor for SampleExtractor {
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        let provenance = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("base64 decode")?;
        let payload: Provenance =
            serde_json::from_slice(&provenance).context("deseralize sample provenance")?;

        let res: Vec<ReferenceValue> = payload
            .rvs
            .iter()
            .filter_map(|(name, values)| {
                Some(
                    ReferenceValue::new()
                        .ok()?
                        .set_name(name)
                        .set_value(values.clone()),
                )
            })
            .collect();

        Ok(res)
    }
}
