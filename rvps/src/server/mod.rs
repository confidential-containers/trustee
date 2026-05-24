use anyhow::{Context, Result};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{debug, info, warn};

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

pub async fn start(
    socket: SocketAddr,
    config: Config,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
) -> Result<()> {
    let service = Rvps::new(config).await?;
    let inner = Arc::new(RwLock::new(service));
    let rvps_server = RvpsServer::new(inner.clone());

    let tls =
        tls_config::grpc::build_grpc_server_tls_config(tls_cert.as_deref(), tls_key.as_deref())
            .await?;

    let mut builder = Server::builder();
    if let Some(tls_config) = tls {
        builder = builder.tls_config(tls_config).context("RVPS TLS config")?;
        info!("RVPS: TLS enabled");
    } else {
        warn!("RVPS: TLS not configured — running in plaintext mode");
    }

    builder
        .add_service(ReferenceValueProviderServiceServer::new(rvps_server))
        .serve(socket)
        .await
        .context("gRPC error")
}
