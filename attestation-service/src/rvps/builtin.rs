use super::{Result, RvpsApi};
use async_trait::async_trait;
use core::result::Result::Ok;
use reference_value_provider_service::{Config, Rvps};
use std::collections::HashMap;

pub struct BuiltinRvps {
    rvps: Rvps,
}

impl BuiltinRvps {
    pub fn new(config: Config) -> Result<Self> {
        let rvps = Rvps::new(config)?;
        Ok(Self { rvps })
    }
}

#[async_trait]
impl RvpsApi for BuiltinRvps {
    fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        self.rvps.verify_and_extract(message)?;
        Ok(())
    }

    fn get_digest(&self, id: String) -> Result<serde_json::Value> {
        let value = self.rvps.get_digest(id)?;

        Ok(value)
    }

    fn get_digests(&self) -> Result<HashMap<String, serde_json::Value>> {
        let values = self.rvps.get_digests()?;

        Ok(values)
    }
}
