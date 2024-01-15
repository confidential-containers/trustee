use anyhow::Result;
use tokio::sync::Mutex;
use crate::rvps::RvpsError;

use self::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

use super::RvpsApi;

pub mod rvps_api {
    tonic::include_proto!("reference");
}

pub struct Agent {
    client: Mutex<ReferenceValueProviderServiceClient<tonic::transport::Channel>>,
}


impl Agent {
    pub async fn new(addr: &str) -> Result<Self, RvpsError> {
        Ok(Self {
            client: Mutex::new(
                ReferenceValueProviderServiceClient::connect(addr.to_string()).await?,
            ),
        })
    }
}
#[async_trait::async_trait]
impl RvpsApi for Agent {
    async fn verify_and_extract(&mut self, message: &str) -> Result<(), RvpsError> {
        let req = tonic::Request::new(ReferenceValueRegisterRequest {
            message: message.to_string(),
        });
        let _ = self
            .client
            .lock()
            .await
            .register_reference_value(req)
            .await?;
        Ok(())
    }

    async fn get_digests(&self, name: &str) -> Result<Vec<String>, RvpsError> {
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            name: name.to_string(),
        });
        let res = self
            .client
            .lock()
            .await
            .query_reference_value(req)
            .await?
            .into_inner();
        let trust_digest = serde_json::from_str(&res.reference_value_results)?;
        Ok(trust_digest)
    }
}
