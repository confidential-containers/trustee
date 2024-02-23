// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;
use serde_json::{json, Value};

pub const DEFAULT_STORAGE_TYPE: &str = "LocalFs";

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub store_type: String,
    pub store_config: Value,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            store_type: DEFAULT_STORAGE_TYPE.to_string(),
            store_config: json!({}),
        }
    }
}
