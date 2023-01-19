use anyhow::{Context, Result};
use attestation_service::rvps::{Core, Store, RVPSAPI};
use log::{debug, info};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::rvps_api::reference_value_provider_service_server::{
    ReferenceValueProviderService, ReferenceValueProviderServiceServer,
};
use crate::rvps_api::{
    ReferenceValueQueryRequest, ReferenceValueQueryResponse, ReferenceValueRegisterRequest,
    ReferenceValueRegisterResponse,
};

pub struct RVPSServer {
    rvps: Arc<Mutex<Core>>,
}

impl RVPSServer {
    pub fn new(rvps: Arc<Mutex<Core>>) -> Self {
        Self { rvps }
    }
}

#[tonic::async_trait]
impl ReferenceValueProviderService for RVPSServer {
    async fn query_reference_value(
        &self,
        request: Request<ReferenceValueQueryRequest>,
    ) -> Result<Response<ReferenceValueQueryResponse>, Status> {
        let request = request.into_inner();

        info!("query {}", request.name);

        let rvs = self
            .rvps
            .lock()
            .await
            .get_digests(&request.name)
            .await
            .map_err(|e| Status::aborted(format!("Query reference value: {e}")))?;
        let reference_value_results = serde_json::to_string(&rvs)
            .map_err(|e| Status::aborted(format!("Serde reference value: {e}")))?;
        info!("Reference values: {}", reference_value_results);

        let res = ReferenceValueQueryResponse {
            reference_value_results,
        };
        Ok(Response::new(res))
    }

    async fn register_reference_value(
        &self,
        request: Request<ReferenceValueRegisterRequest>,
    ) -> Result<Response<ReferenceValueRegisterResponse>, Status> {
        let request = request.into_inner();

        debug!("registry reference value: {}", request.message);

        let message = serde_json::from_str(&request.message)
            .map_err(|e| Status::aborted(format!("Parse message: {e}")))?;
        self.rvps
            .lock()
            .await
            .verify_and_extract(message)
            .await
            .map_err(|e| Status::aborted(format!("Register reference value: {e}")))?;

        let res = ReferenceValueRegisterResponse {};
        Ok(Response::new(res))
    }
}

pub async fn start(socket: SocketAddr, storage: Box<dyn Store + Send + Sync>) -> Result<()> {
    let service = Core::new(storage);
    let inner = Arc::new(Mutex::new(service));
    let rvps_server = RVPSServer::new(inner.clone());

    Server::builder()
        .add_service(ReferenceValueProviderServiceServer::new(rvps_server))
        .serve(socket)
        .await
        .context("gRPC error")
}
