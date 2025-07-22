use actix_web::http::Method;
use anyhow::Result;
use serde::Deserialize;

use super::super::plugin_manager::ClientPlugin;

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SpiffeResourceConfig { 
    pub trust_domain: String,
}

pub struct SpiffeResourcePlugin {  
    trust_domain: String,
}

impl TryFrom<SpiffeResourceConfig> for SpiffeResourcePlugin {
    type Error = anyhow::Error;

    fn try_from(config: SpiffeResourceConfig) -> Result<Self> {
        Ok(Self {
            trust_domain: config.trust_domain,
        })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for SpiffeResourcePlugin {
    async fn handle(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        _method: &Method,
    ) -> Result<Vec<u8>> {
        Ok(format!("Hello from SPIFFE Resource Plugin! Domain: {}", self.trust_domain)
            .as_bytes()
            .to_vec())
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }
}