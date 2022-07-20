use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{Request, Response, Status};
extern crate serde;
use crate::user;
use crate::ATTESTATION_SERVICE;
use tonic::transport::Server;

use crate::attestation_api::attestation_service_server::{
    AttestationService, AttestationServiceServer,
};
use crate::attestation_api::{AttestationRequest, AttestationResponse};

const DEFAULT_ATTESTATION_SOCK: &str = "127.0.0.1:3000";

#[derive(Debug)]
pub struct Service {
    // The default user
    user: Arc<RwLock<user::User>>,
    workdir: PathBuf,
}

impl Service {
    pub fn new(usr: Arc<RwLock<user::User>>, dir: PathBuf) -> Self {
        Self {
            user: usr,
            workdir: dir,
        }
    }
}

#[tonic::async_trait]
impl AttestationService for Service {
    async fn attestation(
        &self,
        request: Request<AttestationRequest>,
    ) -> Result<Response<AttestationResponse>, Status> {
        let request: AttestationRequest = request.into_inner();
        let evidence = std::str::from_utf8(&request.evidence)
            .map_err(|e| Status::invalid_argument(format!("Parse evidence: {}", e)))?
            .to_string();
        debug!("Evidence: {}", evidence);

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let policy = user
            .read()
            .await
            .policy(self.workdir.as_path())
            .await
            .map_err(|e| Status::invalid_argument(format!("Get policy: {}", e)))?;
        let reference_data = user
            .read()
            .await
            .reference_data(self.workdir.as_path())
            .await
            .map_err(|e| Status::invalid_argument(format!("Get reference data: {}", e)))?;

        let attestation_service = Arc::clone(&ATTESTATION_SERVICE);

        let attestation_results = attestation_service
            .attestation(&evidence, policy, reference_data)
            .await
            .map_err(|e| Status::aborted(format!("Attestation: {}", e)))?;

        debug!("Attestation Results: {}", &attestation_results);

        let res = AttestationResponse {
            attestation_results: attestation_results.into_bytes(),
        };

        Ok(Response::new(res))
    }
}

pub async fn start_service(
    socket: Option<&str>,
    usr: Arc<RwLock<user::User>>,
    dir: PathBuf,
) -> Result<()> {
    let socket = socket.unwrap_or(DEFAULT_ATTESTATION_SOCK).parse()?;
    debug!("Attestation listen socket: {}", &socket);
    let service = Service::new(usr, dir);
    Server::builder()
        .add_service(AttestationServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation_api::attestation_service_server::AttestationService;
    use crate::attestation_api::{AttestationRequest, AttestationResponse};
    use crate::common;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha384};
    use std::path::Path;
    use std::sync::Arc;
    use tonic::Request;
    use uuid::Uuid;

    const NONCE: &str = "1234567890";
    const PUBLIC_KEY: &str = "hduabci29e0asdadans0212nsj0e3n";

    fn reference(ver: u64) -> String {
        json!({
            "cpusvn": ver,
            "svn": ver
        })
        .to_string()
    }

    fn evidence() -> String {
        let pubkey = json!({
            "algorithm": "".to_string(),
            "pubkey-length": "".to_string(),
            "pubkey": PUBLIC_KEY.to_string()
        })
        .to_string();
        let mut hasher = Sha384::new();
        hasher.update(NONCE);
        hasher.update(&pubkey);
        let hash = hasher.finalize();
        let tee_evidence = json!({
            "is_debuggable": false,
            "cpusvn": 1,
            "svn": 1,
            "report_data": base64::encode(hash)
        })
        .to_string();
        json!({
            "nonce": NONCE.to_owned(),
            "tee": "sample".to_string(),
            "tee-pubkey": pubkey,
            "tee-evidence": tee_evidence
        })
        .to_string()
    }

    async fn attestation(service: &Service) -> Value {
        let attestaion_request = AttestationRequest {
            evidence: evidence().into_bytes(),
            user: None,
        };
        let request = Request::new(attestaion_request);
        let response = service.attestation(request).await;
        assert!(response.is_ok(), "attestation should success");
        let attestation_response: AttestationResponse = response.unwrap().into_inner();
        let attestation_results = std::str::from_utf8(&attestation_response.attestation_results);
        assert!(
            attestation_results.is_ok(),
            "attestation results should success"
        );
        serde_json::from_str(&attestation_results.unwrap()).unwrap()
    }

    fn create_service(id: Option<&str>) -> (PathBuf, Service) {
        let workdir = Path::new("./").to_owned();
        let user = id.map_or_else(
            || Arc::new(RwLock::new(user::User::default())),
            |id| Arc::new(RwLock::new(user::User::from_str(id).unwrap())),
        );
        let service = Service::new(user.clone(), workdir.clone());
        (workdir, service)
    }

    #[tokio::test]
    async fn test_attestation_default_xxx_allow() {
        let (workdir, service) = create_service(None);

        // Default allow
        let res = attestation(&service).await;
        assert_eq!(res["allow"], true);

        // Default not allow
        let res = service
            .user
            .write()
            .await
            .set_reference_data(service.workdir.as_path(), reference(5))
            .await;
        assert!(res.is_ok(), "Set reference should success");
        let res = attestation(&service).await;
        assert_eq!(res["allow"], false);

        let dir = workdir.join("users").join("default");
        if dir.exists() {
            // delete the temporary user folder
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn test_attestation_allow() {
        let uuid = Uuid::new_v4().to_string();
        let (workdir, service) = create_service(Some(&uuid));
        let res = attestation(&service).await;
        assert_eq!(res["allow"], true);

        let dir = workdir.join("users").join(uuid);
        if dir.exists() {
            // delete the temporary user folder
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn test_attestation_not_allow() {
        let uuid = Uuid::new_v4().to_string();
        let (workdir, service) = create_service(Some(&uuid));
        let res = service
            .user
            .write()
            .await
            .set_reference_data(service.workdir.as_path(), reference(5))
            .await;
        assert!(res.is_ok(), "Set reference should success");
        let res = attestation(&service).await;
        assert_eq!(res["allow"], false);

        let dir = workdir.join("users").join(uuid);
        if dir.exists() {
            // delete the temporary user folder
            std::fs::remove_dir_all(dir).unwrap();
        }
    }

    #[tokio::test]
    async fn test_attestation_multiple_user_failed() {
        let (_, service) = create_service(None);
        let user = common::User {
            id: "testing user".to_string(),
        };
        let attestaion_request = AttestationRequest {
            evidence: evidence().into_bytes(),
            user: Some(user),
        };
        let request = Request::new(attestaion_request);
        let response = service.attestation(request).await;
        assert!(response.is_err(), "attestation should failed");
        let status: Status = response.unwrap_err();
        assert!(
            status.message().contains("Multiple user is not supported"),
            "Should contains multiple user is not supported error"
        );
    }
}
