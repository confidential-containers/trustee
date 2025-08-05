use grpcio::{ChannelBuilder, EnvBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;

use super::{Result, RvpsApi};

#[path = "reference.rs"]
mod reference;

#[path = "reference_grpc.rs"]
mod reference_grpc;

use reference::{
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest, ReferenceValuesQueryRequest,
};
use reference_grpc::ReferenceValueProviderServiceClient;

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

pub struct Agent {
    client: ReferenceValueProviderServiceClient,
}

impl Agent {
    pub async fn new(addr: &str) -> Result<Self> {
        let addr = addr.trim_start_matches("http://");
        let env = Arc::new(EnvBuilder::new().build());
        let channel = ChannelBuilder::new(env).connect(addr);
        let client = ReferenceValueProviderServiceClient::new(channel);
        Ok(Self { client })
    }
}
#[async_trait::async_trait]
impl RvpsApi for Agent {
    fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let mut request = ReferenceValueRegisterRequest::new();
        request.set_message(message.to_string());
        self.client.register_reference_value(&request)?;

        Ok(())
    }

    fn get_digest(&self, id: String) -> Result<serde_json::Value> {
        let mut request = ReferenceValueQueryRequest::new();
        request.set_id(id);

        let response = self.client.query_reference_value(&request);

        let digest = serde_json::from_str(&response?.reference_value_results)?;
        Ok(digest)
    }

    fn get_digests(&self) -> Result<HashMap<String, serde_json::Value>> {
        let request = ReferenceValuesQueryRequest::new();
        let response = self.client.query_reference_values(&request);

        let digest = serde_json::from_str(&response?.reference_value_results)?;
        Ok(digest)
    }
}
