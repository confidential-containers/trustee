use anyhow::*;
use async_trait::async_trait;
use reference_value_provider_service::Core;
use crate::rvps::RvpsError;

use super::RvpsApi;

pub struct Rvps {
    core: Core,
}

impl Rvps {
    pub fn new(store_type: &str) -> Result<Self, RvpsError> {
        Core::new(store_type)
            .map(|core| Self::from_core(core))
            .map_err(|error| RvpsError::CreateRvps(error.to_string()))
    }

    fn from_core(core: Core) -> Self {
        Self { core }
    }
}

#[async_trait]
impl RvpsApi for Rvps {
    async fn verify_and_extract(&mut self, message: &str) -> Result<(), RvpsError> {
        Ok(self.core.verify_and_extract(message).await?)
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
