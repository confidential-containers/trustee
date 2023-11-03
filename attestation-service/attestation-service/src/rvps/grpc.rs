// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use tokio::sync::Mutex;

use self::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

use super::{Message, TrustedDigest, RVPSAPI};

pub mod rvps_api {
    tonic::include_proto!("reference");
}

/// An agent for rvps, uses grpc to connect
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
impl RVPSAPI for Agent {
    async fn verify_and_extract(&mut self, message: Message) -> Result<()> {
        let message = serde_json::to_string(&message)?;
        let req = tonic::Request::new(ReferenceValueRegisterRequest { message });
        let _ = self
            .client
            .lock()
            .await
            .register_reference_value(req)
            .await
            .context("register failed")?;
        Ok(())
    }

    async fn get_digests(&self, name: &str) -> Result<Option<TrustedDigest>> {
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
