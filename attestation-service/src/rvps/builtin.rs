use super::{Result, RvpsApi};
use anyhow::Context;
use async_trait::async_trait;
use core::result::Result::Ok;
use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
use reference_value_provider_service::{
    extractors::ExtractorsConfig, Rvps, REFERENCE_VALUE_STORAGE_INSTANCE,
};
use serde_json::Value;

pub struct BuiltinRvps {
    rvps: Rvps,
}

impl BuiltinRvps {
    pub async fn new(
        config: Option<ExtractorsConfig>,
        storage_type: KeyValueStorageType,
        storage_config: &KeyValueStorageStructConfig,
    ) -> Result<Self> {
        let storage = storage_config
            .to_client_with_namespace(storage_type, REFERENCE_VALUE_STORAGE_INSTANCE)
            .await
            .context("initialize RVPS storage")?;
        let rvps = Rvps::new_with_storage(config, storage)
            .await
            .context("initialize RVPS")?;
        Ok(Self { rvps })
    }
}

#[async_trait]
impl RvpsApi for BuiltinRvps {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        self.rvps.verify_and_extract(message).await?;
        Ok(())
    }

    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let reference_value = self.rvps.query_reference_value(reference_value_id).await?;

        Ok(reference_value)
    }
}
