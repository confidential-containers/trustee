use anyhow::Result;
use attestation_service::{AttestationService as Service, Tee};
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::as_api::attestation_service_server::{AttestationService, AttestationServiceServer};
use crate::as_api::{AttestationRequest, AttestationResponse, Tee as GrpcTee};

const DEFAULT_SOCK: &str = "127.0.0.1:3000";

fn to_kbs_tee(tee: GrpcTee) -> Tee {
    match tee {
        GrpcTee::Sev => Tee::Sev,
        GrpcTee::Sgx => Tee::Sgx,
        GrpcTee::Snp => Tee::Snp,
        GrpcTee::Tdx => Tee::Tdx,
    }
}

pub struct AttestationServer {
    attestation_service: Arc<RwLock<Service>>,
}

impl AttestationServer {
    pub fn new() -> Result<Self> {
        let service = Service::new()?;
        Ok(Self {
            attestation_service: Arc::new(RwLock::new(service)),
        })
    }
}

#[tonic::async_trait]
impl AttestationService for AttestationServer {
    async fn attestation_evaluate(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let request: AttestationRequest = request.into_inner();

        debug!("Evidence: {}", &request.evidence);

        let attestation_results = self
            .attestation_service
            .read()
            .await
            .evaluate(
                to_kbs_tee(
                    GrpcTee::from_i32(request.tee)
                        .ok_or_else(|| Status::aborted(format!("Invalid TEE {}", request.tee)))?,
                ),
                &request.nonce,
                &request.evidence,
            )
            .await
            .map_err(|e| Status::aborted(format!("Attestation: {}", e)))?;

        let results = serde_json::to_string(&attestation_results)
            .map_err(|e| Status::aborted(format!("Parse attestation results: {}", e)))?;

        debug!("Attestation Results: {}", &results);

        let res = AttestationResponse {
            attestation_results: results,
        };
        Ok(Response::new(res))
    }
}

pub async fn start(socket: Option<&str>) -> Result<()> {
    let socket = socket.unwrap_or(DEFAULT_SOCK).parse()?;
    debug!("Listen socket: {}", &socket);

    let attestation_server = AttestationServer::new()?;

    Server::builder()
        .add_service(AttestationServiceServer::new(attestation_server))
        .serve(socket)
        .await?;
    Ok(())
}
