// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Deserialize;
use serde_json::{json, Value};

pub const DEFAULT_STORAGE_TYPE: &str = "LocalFs";

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct Config {
    #[serde(default = "default_store_type")]
    pub store_type: String,

    #[serde(default = "default_store_config")]
    pub store_config: Value,
}

fn default_store_type() -> String {
    DEFAULT_STORAGE_TYPE.to_string()
}

fn default_store_config() -> Value {
    json!({})
}

impl Default for Config {
    fn default() -> Self {
        Self {
            store_type: default_store_type(),
            store_config: json!({}),
        }
    }
}
