use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Mutex;

use self::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

use super::{Result, RvpsApi};

pub mod rvps_api {
    tonic::include_proto!("reference");
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct RvpsRemoteConfig {
    /// Address of remote RVPS. If this field is given, a remote RVPS will be connected to.
    /// If this field is not given, a built-in RVPS will be used.
    #[serde(default = "default_address")]
    pub address: String,
}

fn default_address() -> String {
    "127.0.0.1:50003".into()
}

#[derive(Error, Debug)]
pub enum GrpcRvpsError {
    #[error("Returned status: {0}")]
    Status(#[from] tonic::Status),

    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),
}

pub struct Agent {
    client: Mutex<ReferenceValueProviderServiceClient<tonic::transport::Channel>>,
}

impl Agent {
    pub async fn new(addr: &str) -> Result<Self> {
        Ok(Self {
            client: Mutex::new(
                ReferenceValueProviderServiceClient::connect(addr.to_string()).await?,
            ),
        })
    }
}
#[async_trait::async_trait]
impl RvpsApi for Agent {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
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

    async fn get_digests(&self, name: &str) -> Result<Vec<String>> {
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
