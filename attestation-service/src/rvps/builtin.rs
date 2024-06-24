use super::RvpsApi;
use anyhow::*;
use async_trait::async_trait;
use core::result::Result::Ok;
use reference_value_provider_service::{Config, Core};

pub struct Rvps {
    core: Core,
}

impl Rvps {
    pub fn new(config: Config) -> Result<Self> {
        let core = Core::new(config)?;
        Ok(Self { core })
    }
}

#[async_trait]
impl RvpsApi for Rvps {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        self.core.verify_and_extract(message).await?;
        Ok(())
    }

    async fn get_digests(&self, name: &str) -> Result<Vec<String>> {
        let hashes = self
            .core
            .get_digests(name)
            .await?
            .unwrap_or_default()
            .hash_values;
        Ok(hashes)
    }
}
