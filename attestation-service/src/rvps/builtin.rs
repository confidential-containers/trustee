use super::{Result, RvpsApi};
use async_trait::async_trait;
use core::result::Result::Ok;
use reference_value_provider_service::{Config, Rvps};
use serde_json::Value;

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

    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let reference_value = self.rvps.query_reference_value(reference_value_id).await?;

        Ok(reference_value)
    }
}
