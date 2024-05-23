use anyhow::bail;
use attestation_service::HashAlgorithm;
use attestation_service::{
    config::Config, config::ConfigError, AttestationService as Service, ServiceError, Tee,
};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{debug, info};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::as_api::attestation_service_server::{AttestationService, AttestationServiceServer};
use crate::as_api::{AttestationRequest, AttestationResponse, SetPolicyRequest, SetPolicyResponse};

use crate::rvps_api::reference_value_provider_service_server::{
    ReferenceValueProviderService, ReferenceValueProviderServiceServer,
};

use crate::rvps_api::{
    ReferenceValueQueryRequest, ReferenceValueQueryResponse, ReferenceValueRegisterRequest,
    ReferenceValueRegisterResponse,
};

fn to_kbs_tee(tee: &str) -> anyhow::Result<Tee> {
    let tee = match tee {
        "sev" => Tee::Sev,
        "sgx" => Tee::Sgx,
        "snp" => Tee::Snp,
        "tdx" => Tee::Tdx,
        "csv" => Tee::Csv,
        "sample" => Tee::Sample,
        "azsnpvtpm" => Tee::AzSnpVtpm,
        "cca" => Tee::Cca,
        "aztdxvtpm" => Tee::AzTdxVtpm,
        other => bail!("Unsupported TEE type: {other}"),
    };

    Ok(tee)
}

#[derive(Error, Debug)]
pub enum GrpcError {
    #[error("Read AS config file failed: {0}")]
    Config(#[source] ConfigError),
    #[error("Creating attestation service failed: {0}")]
    Service(#[from] ServiceError),
    #[error("tonic transport error: {0}")]
    TonicTransport(#[from] tonic::transport::Error),
}

pub struct AttestationServer {
    attestation_service: Service,
}

impl AttestationServer {
    pub async fn new(config_path: Option<String>) -> Result<Self, GrpcError> {
        let config = match config_path {
            Some(path) => Config::try_from(Path::new(&path)).map_err(GrpcError::Config)?,
            None => Config::default(),
        };

        let service = Service::new(config).await?;

        Ok(Self {
            attestation_service: service,
        })
    }
}

#[tonic::async_trait]
impl AttestationService for Arc<RwLock<AttestationServer>> {
    async fn set_attestation_policy(
        &self,
        request: Request<SetPolicyRequest>,
    ) -> Result<Response<SetPolicyResponse>, Status> {
        let request: SetPolicyRequest = request.into_inner();

        info!("SetPolicy API called.");
        debug!("SetPolicyInput: {request:#?}");

        self.write()
            .await
            .attestation_service
            .set_policy(request.policy_id, request.policy)
            .await
            .map_err(|e| Status::aborted(format!("Set Attestation Policy Failed: {e}")))?;

        Ok(Response::new(SetPolicyResponse {}))
    }

    async fn attestation_evaluate(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let request: AttestationRequest = request.into_inner();

        info!("AttestationEvaluate API called.");
        debug!("Evidence: {}", &request.evidence);

        let tee = to_kbs_tee(&request.tee)
            .map_err(|e| Status::aborted(format!("parse TEE type: {e}")))?;
        let evidence = URL_SAFE_NO_PAD
            .decode(request.evidence)
            .map_err(|e| Status::aborted(format!("Illegal input Evidence: {e}")))?;

        let runtime_data = match request.runtime_data {
            Some(runtime_data) => match runtime_data {
                crate::as_api::attestation_request::RuntimeData::RawRuntimeData(raw) => {
                    let raw_runtime = URL_SAFE_NO_PAD
                        .decode(raw)
                        .map_err(|e| Status::aborted(format!("base64 decode runtime data: {e}")))?;
                    Some(attestation_service::Data::Raw(raw_runtime))
                }
                crate::as_api::attestation_request::RuntimeData::StructuredRuntimeData(
                    structured,
                ) => {
                    let structured = serde_json::from_str(&structured).map_err(|e| {
                        Status::aborted(format!("parse structured runtime data: {e}"))
                    })?;
                    Some(attestation_service::Data::Structured(structured))
                }
            },
            None => None,
        };

        let init_data = match request.init_data {
            Some(init_data) => match init_data {
                crate::as_api::attestation_request::InitData::RawInitData(raw) => {
                    let raw_init = URL_SAFE_NO_PAD
                        .decode(raw)
                        .map_err(|e| Status::aborted(format!("base64 decode init data: {e}")))?;
                    Some(attestation_service::Data::Raw(raw_init))
                }
                crate::as_api::attestation_request::InitData::StructuredInitData(structured) => {
                    let structured = serde_json::from_str(&structured)
                        .map_err(|e| Status::aborted(format!("parse structured init data: {e}")))?;
                    Some(attestation_service::Data::Structured(structured))
                }
            },
            None => None,
        };

        let runtime_data_hash_algorithm = match request.runtime_data_hash_algorithm.is_empty() {
            false => {
                HashAlgorithm::try_from(&request.runtime_data_hash_algorithm[..]).map_err(|e| {
                    Status::aborted(format!("parse runtime data HashAlgorithm failed: {e}"))
                })?
            }
            true => {
                info!("No Runtime Data Hash Algorithm provided, use `sha384` by default.");
                HashAlgorithm::Sha384
            }
        };

        let init_data_hash_algorithm = match request.init_data_hash_algorithm.is_empty() {
            false => {
                HashAlgorithm::try_from(&request.init_data_hash_algorithm[..]).map_err(|e| {
                    Status::aborted(format!("parse init data HashAlgorithm failed: {e}"))
                })?
            }
            true => {
                info!("No Init Data Hash Algorithm provided, use `sha384` by default.");
                HashAlgorithm::Sha384
            }
        };

        let policy_ids = match request.policy_ids.is_empty() {
            true => vec!["default".into()],
            false => request.policy_ids,
        };

        let attestation_token = self
            .read()
            .await
            .attestation_service
            .evaluate(
                evidence,
                tee,
                runtime_data,
                runtime_data_hash_algorithm,
                init_data,
                init_data_hash_algorithm,
                policy_ids,
            )
            .await
            .map_err(|e| Status::aborted(format!("Attestation: {e:?}")))?;

        debug!("Attestation Token: {}", &attestation_token);

        let res = AttestationResponse { attestation_token };
        Ok(Response::new(res))
    }
}

#[tonic::async_trait]
impl ReferenceValueProviderService for Arc<RwLock<AttestationServer>> {
    async fn query_reference_value(
        &self,
        _request: Request<ReferenceValueQueryRequest>,
    ) -> Result<Response<ReferenceValueQueryResponse>, Status> {
        let status =
            Status::aborted("Cannot query reference values using RVPS as a submodule in AS.");

        Err(status)
    }

    async fn register_reference_value(
        &self,
        request: Request<ReferenceValueRegisterRequest>,
    ) -> Result<Response<ReferenceValueRegisterResponse>, Status> {
        let request = request.into_inner();

        info!("RegisterReferenceValue API called.");
        debug!("registry reference value: {}", request.message);

        let message = serde_json::from_str(&request.message)
            .map_err(|e| Status::aborted(format!("Parse message: {e}")))?;
        self.write()
            .await
            .attestation_service
            .register_reference_value(message)
            .await
            .map_err(|e| Status::aborted(format!("Register reference value: {e}")))?;

        let res = ReferenceValueRegisterResponse {};
        Ok(Response::new(res))
    }
}

pub async fn start(socket: SocketAddr, config_path: Option<String>) -> Result<(), GrpcError> {
    info!("Listen socket: {}", &socket);

    let attestation_server = Arc::new(RwLock::new(AttestationServer::new(config_path).await?));

    Server::builder()
        .add_service(AttestationServiceServer::new(attestation_server.clone()))
        .add_service(ReferenceValueProviderServiceServer::new(attestation_server))
        .serve(socket)
        .await?;
    Ok(())
}
