//! Simple echo plugin server for integration testing.
//!
//! This server implements the KbsPlugin gRPC service and echoes back
//! request details in the response body.

use tonic::{
    transport::{Identity, Server, ServerTlsConfig},
    Request, Response, Status,
};
use tonic_health::server::health_reporter;

pub mod plugin_api {
    tonic::include_proto!("kbs.plugin.v1");
}

use plugin_api::{
    kbs_plugin_server::{KbsPlugin, KbsPluginServer},
    GetCapabilitiesRequest, GetCapabilitiesResponse, NeedsEncryptionRequest,
    NeedsEncryptionResponse, PluginRequest, PluginResponse, ValidateAuthRequest,
    ValidateAuthResponse,
};

const LISTEN_ADDR_ENV: &str = "ECHO_PLUGIN_LISTEN_ADDR";
const TLS_CERT_ENV: &str = "ECHO_PLUGIN_TLS_CERT";
const TLS_KEY_ENV: &str = "ECHO_PLUGIN_TLS_KEY";

#[derive(Default)]
pub struct EchoPlugin;

#[tonic::async_trait]
impl KbsPlugin for EchoPlugin {
    async fn handle(
        &self,
        request: Request<PluginRequest>,
    ) -> Result<Response<PluginResponse>, Status> {
        let req = request.into_inner();

        // Echo back request details
        let response_body = format!(
            "Echo: method={}, path={:?}, query={:?}, body_len={}",
            req.method,
            req.path,
            req.query,
            req.body.len()
        );

        let reply = PluginResponse {
            body: response_body.into_bytes(),
            status_code: 200,
            content_type: "text/plain".to_string(),
        };

        Ok(Response::new(reply))
    }

    async fn get_capabilities(
        &self,
        _request: Request<GetCapabilitiesRequest>,
    ) -> Result<Response<GetCapabilitiesResponse>, Status> {
        let reply = GetCapabilitiesResponse {
            name: "echo-plugin".to_string(),
            version: "1.0.0".to_string(),
            supported_methods: vec!["GET".to_string(), "POST".to_string()],
            attributes: Default::default(),
        };

        Ok(Response::new(reply))
    }

    // Require admin authentication for paths rooted at "admin" (e.g.
    // /kbs/v0/echo-test/admin/...), attestation-gated for all other paths.
    // This demonstrates per-request dynamic auth decisions: the same plugin
    // binary serves both admin-gated and attestation-gated routes.
    async fn validate_auth(
        &self,
        request: Request<ValidateAuthRequest>,
    ) -> Result<Response<ValidateAuthResponse>, Status> {
        let requires_admin_auth = request
            .into_inner()
            .path
            .first()
            .map(|s| s == "admin")
            .unwrap_or(false);
        Ok(Response::new(ValidateAuthResponse {
            requires_admin_auth,
        }))
    }

    // The echo plugin returns non-sensitive data; no JWE encryption needed.
    async fn needs_encryption(
        &self,
        _request: Request<NeedsEncryptionRequest>,
    ) -> Result<Response<NeedsEncryptionResponse>, Status> {
        Ok(Response::new(NeedsEncryptionResponse { encrypt: false }))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::var(LISTEN_ADDR_ENV)
        .unwrap_or_else(|_| "127.0.0.1:50051".to_string())
        .parse()?;
    let echo_plugin = EchoPlugin::default();

    // Register health service so KBS health checks succeed
    let (health_reporter, health_service) = health_reporter();
    health_reporter
        .set_serving::<KbsPluginServer<EchoPlugin>>()
        .await;

    let tls_cert = std::env::var(TLS_CERT_ENV).ok();
    let tls_key = std::env::var(TLS_KEY_ENV).ok();

    let mut builder = Server::builder();

    if let (Some(cert_path), Some(key_path)) = (tls_cert, tls_key) {
        let cert = std::fs::read(&cert_path)?;
        let key = std::fs::read(&key_path)?;
        let identity = Identity::from_pem(cert, key);
        let tls_config = ServerTlsConfig::new().identity(identity);
        builder = builder.tls_config(tls_config)?;
        println!("Echo plugin server listening on {} (TLS)", addr);
    } else {
        println!("Echo plugin server listening on {} (plaintext)", addr);
    }

    builder
        .add_service(health_service)
        .add_service(KbsPluginServer::new(echo_plugin))
        .serve(addr)
        .await?;

    Ok(())
}
