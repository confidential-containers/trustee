use anyhow::{Context, Result};
use reference_value_provider_service::{config::DEFAULT_STORAGE_TYPE, Config as CrateConfig};
use serde::Deserialize;
use serde_json::{json, Value};

const DEFAULT_ADDR: &str = "127.0.0.1:50003";

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    pub address: String,
    pub store_type: String,
    pub store_config: Value,
}

impl From<Config> for CrateConfig {
    fn from(val: Config) -> CrateConfig {
        CrateConfig {
            store_type: val.store_type,
            store_config: val.store_config,
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            store_type: DEFAULT_STORAGE_TYPE.to_string(),
            store_config: json!({}),
            address: DEFAULT_ADDR.to_string(),
        }
    }
}

impl Config {
    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;

        let res = c.try_deserialize().context("invalid config")?;
        Ok(res)
    }
}
