use anyhow::{Context, Result};
use log::{debug, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::{Config, Rvps};

use crate::rvps_api::reference::reference_value_provider_service_server::{
    ReferenceValueProviderService, ReferenceValueProviderServiceServer,
};
use crate::rvps_api::reference::{
    ReferenceValueQueryRequest, ReferenceValueQueryResponse, ReferenceValueRegisterRequest,
    ReferenceValueRegisterResponse,
};

pub struct RvpsServer {
    rvps: Arc<RwLock<Rvps>>,
}

impl RvpsServer {
    pub fn new(rvps: Arc<RwLock<Rvps>>) -> Self {
        Self { rvps }
    }
}

#[tonic::async_trait]
impl ReferenceValueProviderService for RvpsServer {
    async fn query_reference_value(
        &self,
        request: Request<ReferenceValueQueryRequest>,
    ) -> Result<Response<ReferenceValueQueryResponse>, Status> {
        let rvs = self
            .rvps
            .read()
            .await
            .query_reference_value(&request.into_inner().reference_value_id)
            .await
            .map_err(|e| Status::aborted(format!("Query reference value: {e}")))?;

        let reference_value_results = match rvs {
            Some(rvs) => Some(
                serde_json::to_string(&rvs)
                    .map_err(|e| Status::aborted(format!("Serde reference value: {e}")))?,
            ),
            None => None,
        };

        info!("Reference values: {:?}", reference_value_results);

        Ok(Response::new(ReferenceValueQueryResponse {
            reference_value_results,
        }))
    }

    async fn register_reference_value(
        &self,
        request: Request<ReferenceValueRegisterRequest>,
    ) -> Result<Response<ReferenceValueRegisterResponse>, Status> {
        let request = request.into_inner();

        debug!("registry reference value: {}", request.message);

        self.rvps
            .write()
            .await
            .verify_and_extract(&request.message)
            .await
            .map_err(|e| Status::aborted(format!("Register reference value: {e}")))?;

        let res = ReferenceValueRegisterResponse {};
        Ok(Response::new(res))
    }
}

pub async fn start(socket: SocketAddr, config: Config) -> Result<()> {
    let service = Rvps::new(config)?;
    let inner = Arc::new(RwLock::new(service));
    let rvps_server = RvpsServer::new(inner.clone());

    Server::builder()
        .add_service(ReferenceValueProviderServiceServer::new(rvps_server))
        .serve(socket)
        .await
        .context("gRPC error")
}
