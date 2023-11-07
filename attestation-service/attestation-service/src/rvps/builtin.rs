use anyhow::*;
use async_trait::async_trait;
use reference_value_provider_service::Core;

use super::RvpsApi;

pub struct Rvps {
    core: Core,
}

impl Rvps {
    pub fn new(store_type: &str) -> Result<Self> {
        let core = Core::new(store_type)?;
        Ok(Self { core })
    }
}

#[async_trait]
impl RvpsApi for Rvps {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        self.core.verify_and_extract(message).await
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
