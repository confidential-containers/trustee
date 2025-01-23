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
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        self.rvps.verify_and_extract(message).await?;
        Ok(())
    }

    async fn get_digests(&self) -> Result<HashMap<String, Vec<String>>> {
        let hashes = self.rvps.get_digests().await?;

        Ok(hashes)
    }
}
