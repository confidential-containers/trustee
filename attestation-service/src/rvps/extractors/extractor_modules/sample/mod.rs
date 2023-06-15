// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This is a very simple format of provenance

use std::collections::HashMap;

use anyhow::*;
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use serde::{Deserialize, Serialize};

use crate::rvps::{
    reference_value::{HashValuePair, REFERENCE_VALUE_VERSION},
    ReferenceValue,
};

use super::Extractor;

#[derive(Serialize, Deserialize)]
pub struct Provenance {
    #[serde(flatten)]
    rvs: HashMap<String, Vec<String>>,
}

#[derive(Default)]
pub struct SampleExtractor;

/// Default reference value hash algorithm
const DEFAULT_ALG: &str = "sha384";

/// The reference value will be expired in the default time (months)
const DEFAULT_EXPIRED_TIME: u32 = 12;

impl Extractor for SampleExtractor {
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        let provenance = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("base64 decode")?;
        let payload: Provenance =
            serde_json::from_slice(&provenance).context("deseralize sample provenance")?;

        let res = payload
            .rvs
            .iter()
            .filter_map(|(name, rvalues)| {
                let rvs = rvalues
                    .iter()
                    .map(|rv| HashValuePair::new(DEFAULT_ALG.into(), rv.to_string()))
                    .collect();

                let time = Utc::now()
                    .with_nanosecond(0)
                    .and_then(|t| t.checked_add_months(Months::new(DEFAULT_EXPIRED_TIME)));
                match time {
                    Some(expired) => Some(ReferenceValue {
                        version: REFERENCE_VALUE_VERSION.into(),
                        name: name.to_string(),
                        expired,
                        hash_value: rvs,
                    }),
                    None => {
                        warn!("Expired time calculated overflowed for reference value of {name}.");
                        None
                    }
                }
            })
            .collect();

        Ok(res)
    }
}
