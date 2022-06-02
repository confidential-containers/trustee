use crate::management_api::Tee;
use crate::user;
use anyhow::Result;
use attestation_service::Service as AS;
use attestation_service::TEE;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use crate::management_api::management_service_server::{
    ManagementService, ManagementServiceServer,
};
use crate::management_api::{
    GetPolicyRequest, GetPolicyResponse, GetReferenceDataRequest, GetReferenceDataResponse,
    RestoreDefaultPolicyRequest, RestoreDefaultPolicyResponse, RestoreDefaultReferenceDataRequest,
    RestoreDefaultReferenceDataResponse, SetPolicyRequest, SetPolicyResponse,
    SetReferenceDataRequest, SetReferenceDataResponse,
};

const DEFAULT_MANAGEMENT_SOCK: &str = "127.0.0.1:3001";

impl Tee {
    // Convert to attestation_service::TEE
    fn convert_to_tee(&self) -> TEE {
        match self {
            Tee::Sgx => TEE::SGX,
            Tee::Tdx => TEE::TDX,
            Tee::SevSnp => TEE::SEVSNP,
            Tee::Sample => TEE::SAMPLE,
        }
    }
}

// Implemenmt for .to_string()
impl fmt::Display for Tee {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let str = match self {
            Tee::Sgx => "sgx",
            Tee::Tdx => "tdx",
            Tee::SevSnp => "sevsnp",
            Tee::Sample => "sample",
        };
        write!(f, "{}", str)
    }
}

#[derive(Debug)]
pub struct Service {
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
impl ManagementService for Service {
    async fn set_policy(
        &self,
        request: Request<SetPolicyRequest>,
    ) -> Result<Response<SetPolicyResponse>, Status> {
        let request: SetPolicyRequest = request.into_inner();
        let policy = std::str::from_utf8(&request.content)
            .map_err(|e| Status::invalid_argument(format!("Parse content: {}", e)))?
            .to_owned();
        debug!("Policy: {}", &policy);

        // Check new policy's syntax
        AS::new()
            .map_err(|e| Status::aborted(format!("Create AS: {}", e)))?
            .opa_test(policy.clone(), "{}".to_string(), "{}".to_string())
            .map_err(|e| Status::aborted(format!("Syntax: {}", e)))?;

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let tee: Tee = Tee::from_i32(request.tee)
            .ok_or_else(|| Status::invalid_argument("Tee type isn't supported"))?;
        user.write()
            .await
            .set_policy(self.workdir.as_path(), tee.to_string(), policy)
            .await
            .map_err(|e| Status::aborted(format!("Failure: {}", e)))?;

        Ok(Response::new(SetPolicyResponse {}))
    }

    async fn set_reference_data(
        &self,
        request: Request<SetReferenceDataRequest>,
    ) -> Result<Response<SetReferenceDataResponse>, Status> {
        let request: SetReferenceDataRequest = request.into_inner();
        let reference_data = std::str::from_utf8(&request.content)
            .map_err(|e| Status::invalid_argument(format!("Parse content: {}", e)))?;
        debug!("Reference data:\n{}", reference_data);

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let tee: Tee = Tee::from_i32(request.tee)
            .ok_or_else(|| Status::invalid_argument("Tee type isn't supported"))?;
        user.write()
            .await
            .set_reference_data(
                self.workdir.as_path(),
                tee.to_string(),
                reference_data.to_owned(),
            )
            .await
            .map_err(|e| Status::aborted(format!("Failure: {}", e)))?;

        Ok(Response::new(SetReferenceDataResponse {}))
    }

    async fn get_policy(
        &self,
        request: Request<GetPolicyRequest>,
    ) -> Result<Response<GetPolicyResponse>, Status> {
        let request: GetPolicyRequest = request.into_inner();

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let tee: Tee = Tee::from_i32(request.tee)
            .ok_or_else(|| Status::invalid_argument("Tee type isn't supported"))?;
        let policy = user
            .read()
            .await
            .policy(self.workdir.as_path(), tee.to_string())
            .await
            .map_err(|e| Status::invalid_argument(format!("Get policy: {}", e)))?;
        let policy = match policy {
            Some(policy) => Ok(policy),
            None => {
                AS::new()
                    .map_err(|e| Status::aborted(format!("Create AS: {}", e)))?
                    .default_policy(tee.convert_to_tee())
                    .await
            }
        }
        .map_err(|e| Status::aborted(format!("Get policy: {}", e)))?;
        debug!("Policy: {}", policy);
        let res = GetPolicyResponse {
            content: policy.into_bytes(),
        };

        Ok(Response::new(res))
    }

    async fn get_reference_data(
        &self,
        request: Request<GetReferenceDataRequest>,
    ) -> Result<Response<GetReferenceDataResponse>, Status> {
        let request: GetReferenceDataRequest = request.into_inner();

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let tee: Tee = Tee::from_i32(request.tee)
            .ok_or_else(|| Status::invalid_argument("Tee type isn't supported"))?;
        let reference_data = user
            .read()
            .await
            .reference_data(self.workdir.as_path(), tee.to_string())
            .await
            .map_err(|e| Status::invalid_argument(format!("Get reference data: {}", e)))?;
        let reference_data = match reference_data {
            Some(reference_data) => Ok(reference_data),
            None => {
                AS::new()
                    .map_err(|e| Status::aborted(format!("Create AS failed: {}", e)))?
                    .default_reference_data(tee.convert_to_tee())
                    .await
            }
        }
        .map_err(|e| Status::aborted(format!("Get reference data: {}", e)))?;
        debug!("Reference: {}", reference_data);
        let res = GetReferenceDataResponse {
            content: reference_data.into_bytes(),
        };

        Ok(Response::new(res))
    }

    async fn restore_default_policy(
        &self,
        request: Request<RestoreDefaultPolicyRequest>,
    ) -> Result<Response<RestoreDefaultPolicyResponse>, Status> {
        let request: RestoreDefaultPolicyRequest = request.into_inner();

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let tee: Tee = Tee::from_i32(request.tee)
            .ok_or_else(|| Status::invalid_argument("Tee type is not supported"))?;
        user.write()
            .await
            .delete_policy(self.workdir.as_path(), tee.to_string())
            .await
            .map_err(|e| Status::aborted(format!("Failure: {}", e)))?;

        Ok(Response::new(RestoreDefaultPolicyResponse {}))
    }

    async fn restore_default_reference_data(
        &self,
        request: Request<RestoreDefaultReferenceDataRequest>,
    ) -> Result<Response<RestoreDefaultReferenceDataResponse>, Status> {
        let request: RestoreDefaultReferenceDataRequest = request.into_inner();

        let user: &Arc<RwLock<user::User>> = request.user.map_or_else(
            || Ok(&self.user),
            |_user| Err(Status::invalid_argument("Multiple user is not supported")),
        )?;

        let tee: Tee = Tee::from_i32(request.tee)
            .ok_or_else(|| Status::invalid_argument("Tee type is not supported"))?;
        user.write()
            .await
            .delete_reference_data(self.workdir.as_path(), tee.to_string())
            .await
            .map_err(|e| Status::aborted(format!("Failure: {}", e)))?;

        Ok(Response::new(RestoreDefaultReferenceDataResponse {}))
    }
}

pub async fn start_service(
    socket: Option<&str>,
    usr: Arc<RwLock<user::User>>,
    dir: PathBuf,
) -> Result<()> {
    let socket = socket.unwrap_or(DEFAULT_MANAGEMENT_SOCK).parse()?;
    debug!("Management listen socket: {}", &socket);
    let service = Service::new(usr, dir);
    let _server = Server::builder()
        .add_service(ManagementServiceServer::new(service))
        .serve(socket)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::management_api::management_service_server::ManagementService;
    use crate::management_api::Tee;
    use serde_json::{json, Value};
    use std::path::Path;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use uuid::Uuid;

    fn reference(ver: u64) -> String {
        json!({
            "cpusvn": ver,
            "svn": ver
        })
        .to_string()
    }

    fn default_policy() -> String {
        let policy = r#"package policy

# By default, deny requests.
default allow = false

allow {
    input.cpusvn >= data.cpusvn
    input.svn >= data.svn
}"#;
        policy.to_string()
    }

    fn policy() -> String {
        let policy = r#"package policy

# By default, deny requests.
default allow = false

allow {
    cpusvn
    svn
}

cpusvn {
    input.cpusvn >= data.cpusvn
}
svn {
    input.svn >= data.svn
}"#;
        policy.to_string()
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

    async fn get_policy(service: &Service) -> GetPolicyResponse {
        let request = GetPolicyRequest {
            tee: Tee::Sample as i32,
            user: None,
        };
        let request = Request::new(request);
        let response = service.get_policy(request).await;
        assert!(response.is_ok(), "Get policy should success");
        response.unwrap().into_inner()
    }

    async fn set_policy(
        service: &Service,
        policy: String,
    ) -> Result<Response<SetPolicyResponse>, Status> {
        let request = SetPolicyRequest {
            tee: Tee::Sample as i32,
            user: None,
            content: policy.into_bytes(),
        };
        let request = Request::new(request);
        service.set_policy(request).await
    }

    async fn restore_default_policy(service: &Service) {
        let request = RestoreDefaultPolicyRequest {
            tee: Tee::Sample as i32,
            user: None,
        };
        let request = Request::new(request);
        let response = service.restore_default_policy(request).await;
        assert!(response.is_ok(), "Reset policy should success");
    }

    #[tokio::test]
    async fn test_xxx_policy() {
        let uuid = Uuid::new_v4().to_string();
        let (workdir, service) = create_service(Some(&uuid));

        // Get default policy
        let response: GetPolicyResponse = get_policy(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Policy content should OK");
        assert!(
            content.unwrap().to_string() == default_policy(),
            "The default policy should equal."
        );

        // Set customized policy
        let res = set_policy(&service, policy()).await;
        assert!(res.is_ok(), "Set policy should success");

        // Get the customized policy file.
        let response = get_policy(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Policy content should OK");
        assert!(
            content.unwrap() == policy(),
            "The customized policy should equal."
        );

        let userdir = workdir.join("users").join(uuid);
        if userdir.exists() {
            // Delete the temporary user folder
            std::fs::remove_dir_all(userdir).unwrap();
        }
    }

    #[tokio::test]
    async fn test_restore_default_policy() {
        let uuid = Uuid::new_v4().to_string();
        let (workdir, service) = create_service(Some(&uuid));

        // Set customized policy
        let res = set_policy(&service, policy()).await;
        assert!(res.is_ok(), "Set policy should success");
        // Get the customized policy file.
        let response = get_policy(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Policy content should OK");
        assert!(
            content.unwrap() == policy(),
            "The customized policy should equal."
        );

        // Restore the customized policy.
        restore_default_policy(&service).await;

        // Get default policy
        let response: GetPolicyResponse = get_policy(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Policy content should OK");
        assert!(
            content.unwrap().to_string() == default_policy(),
            "The default policy should equal."
        );

        let userdir = workdir.join("users").join(uuid);
        if userdir.exists() {
            // Delete the temporary user folder
            std::fs::remove_dir_all(userdir).unwrap();
        }
    }

    #[tokio::test]
    async fn test_set_policy_illegal() {
        let policy_illegal = r#"package policy
# By default, deny requests.
default allow = false
allow {
    cpusvn
}"#;
        let (_, service) = create_service(None);

        let response = set_policy(&service, policy_illegal.to_string()).await;
        assert!(response.is_err(), "Set policy should not success");
        let status: Status = response.unwrap_err();
        assert!(
            status
                .message()
                .contains("policy.rego:5: rego_unsafe_var_error: var cpusvn is unsafe"),
            "Should contains .rego error"
        );
    }

    async fn get_reference_data(service: &Service) -> GetReferenceDataResponse {
        let request = GetReferenceDataRequest {
            tee: Tee::Sample as i32,
            user: None,
        };
        let request = Request::new(request);
        let response = service.get_reference_data(request).await;
        assert!(response.is_ok(), "Get reference data should success");
        response.unwrap().into_inner()
    }

    async fn set_reference_data(
        service: &Service,
        reference_data: String,
    ) -> Result<Response<SetReferenceDataResponse>, Status> {
        let request = SetReferenceDataRequest {
            tee: Tee::Sample as i32,
            user: None,
            content: reference_data.into_bytes(),
        };
        let request = Request::new(request);
        service.set_reference_data(request).await
    }

    async fn restore_default_reference_data(service: &Service) {
        let request = RestoreDefaultReferenceDataRequest {
            tee: Tee::Sample as i32,
            user: None,
        };
        let request = Request::new(request);
        let response = service.restore_default_reference_data(request).await;
        assert!(response.is_ok(), "Reset reference data should success");
    }

    #[tokio::test]
    async fn test_xxx_reference_data() {
        let uuid = Uuid::new_v4().to_string();
        let (workdir, service) = create_service(Some(&uuid));

        // Get the default reference data
        let response = get_reference_data(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Reference data content should OK");
        let v: Value = serde_json::from_str(&content.unwrap()).unwrap();
        assert!(v["svn"].as_u64().unwrap() == 0, "The default svn == 0.");
        assert!(
            v["cpusvn"].as_u64().unwrap() == 0,
            "The default cpusvn == 0."
        );

        // Set the customized reference data
        let res = set_reference_data(&service, reference(5)).await;
        assert!(res.is_ok(), "Set reference data should success");

        // Get the customized reference data
        let response = get_reference_data(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Reference data content should OK");
        let v: Value = serde_json::from_str(&content.unwrap()).unwrap();
        assert!(v["svn"].as_u64().unwrap() == 5, "The customized svn == 0.");
        assert!(
            v["cpusvn"].as_u64().unwrap() == 5,
            "The customized cpusvn == 0."
        );

        let userdir = workdir.join("users").join(uuid);
        if userdir.exists() {
            // Delete the temporary user folder
            std::fs::remove_dir_all(userdir).unwrap();
        }
    }

    #[tokio::test]
    async fn test_restore_default_reference_data() {
        let uuid = Uuid::new_v4().to_string();
        let (workdir, service) = create_service(Some(&uuid));

        // Set the customized reference data
        let res = set_reference_data(&service, reference(5)).await;
        assert!(res.is_ok(), "Set reference data should success");
        // Get the customized reference data
        let response = get_reference_data(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Reference data content should OK");
        let v: Value = serde_json::from_str(&content.unwrap()).unwrap();
        assert!(v["svn"].as_u64().unwrap() == 5, "The customized svn == 0.");
        assert!(
            v["cpusvn"].as_u64().unwrap() == 5,
            "The customized cpusvn == 0."
        );

        // Restore the reference data.
        restore_default_reference_data(&service).await;

        // Get the default reference data
        let response = get_reference_data(&service).await;
        let content = std::str::from_utf8(&response.content);
        assert!(content.is_ok(), "Reference data content should OK");
        let v: Value = serde_json::from_str(&content.unwrap()).unwrap();
        assert!(v["svn"].as_u64().unwrap() == 0, "The default svn == 0.");
        assert!(
            v["cpusvn"].as_u64().unwrap() == 0,
            "The default cpusvn == 0."
        );

        let userdir = workdir.join("users").join(uuid);
        if userdir.exists() {
            // Delete the temporary user folder
            std::fs::remove_dir_all(userdir).unwrap();
        }
    }
}
