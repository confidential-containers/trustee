use anyhow::Context;
use mobc::{Manager, Pool};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use tls_config::grpc::GrpcTlsMode;
use tonic::transport::{Channel, ClientTlsConfig};
use tracing::{debug, info};

use self::rvps_api::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

use super::{Result, RvpsApi};

pub mod rvps_api {
    tonic::include_proto!("reference");
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct RvpsRemoteConfig {
    /// Address of remote RVPS. If this field is given, a remote RVPS will be connected to.
    /// If this field is not given, a built-in RVPS will be used.
    #[serde(default = "default_address")]
    pub address: String,
    /// TLS mode for the gRPC channel. Default: `insecure` (plaintext).
    #[serde(default)]
    pub tls_mode: GrpcTlsMode,
    /// Path to a PEM CA certificate used to verify the RVPS server certificate.
    /// Required when `tls_mode = "tls"`.
    #[serde(default)]
    pub ca_cert_path: Option<PathBuf>,
}

fn default_address() -> String {
    "127.0.0.1:50003".into()
}

impl Default for RvpsRemoteConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            tls_mode: GrpcTlsMode::Insecure,
            ca_cert_path: None,
        }
    }
}

/// The default pool size for the RVPS client.
const DEFAULT_RVPS_POOL_SIZE: u64 = 10;

pub struct Agent {
    pool: Pool<GrpcManager>,
}

impl Agent {
    pub async fn new(config: &RvpsRemoteConfig) -> Result<Self> {
        info!(
            "connect to remote RVPS [{}] with pool size {}",
            config.address, DEFAULT_RVPS_POOL_SIZE
        );

        // Tonic uses the URI scheme (not the TLS config object) to decide whether
        // to activate TLS, so an explicit http:// with tls_mode="tls" would
        // silently connect in plaintext. Reject contradictions up front.
        if config.address.starts_with("https://") && config.tls_mode != GrpcTlsMode::Tls {
            return Err(anyhow::anyhow!(
                "RVPS gRPC: tls_mode=\"insecure\" requires an http:// address, got \"{}\"",
                config.address
            )
            .into());
        }
        if config.address.starts_with("http://") && config.tls_mode == GrpcTlsMode::Tls {
            return Err(anyhow::anyhow!(
                "RVPS gRPC: tls_mode=\"tls\" requires an https:// address, got \"{}\"",
                config.address
            )
            .into());
        }

        // Auto-prepend the correct scheme if none was given.
        let address =
            if !config.address.starts_with("http://") && !config.address.starts_with("https://") {
                let scheme = if config.tls_mode == GrpcTlsMode::Tls {
                    "https"
                } else {
                    "http"
                };
                debug!(
                    "add {scheme}:// prefix to the rvps grpc address [{}]",
                    config.address
                );
                format!("{scheme}://{}", config.address)
            } else {
                config.address.clone()
            };

        let tls_config = tls_config::grpc::build_grpc_client_tls_config(
            &config.tls_mode,
            config.ca_cert_path.as_deref(),
        )
        .await
        .context("RVPS gRPC client TLS")?;

        let manager = GrpcManager {
            address,
            tls_config,
        };
        let pool = Pool::builder()
            .max_open(DEFAULT_RVPS_POOL_SIZE)
            .build(manager);

        // the mobc Pool builder does not establish an actual connection,
        // so we need to test the connection and validate the parameters at launch time
        let _client = pool.get().await?;
        Ok(Self { pool })
    }
}
#[async_trait::async_trait]
impl RvpsApi for Agent {
    async fn verify_and_extract(&mut self, message: &str) -> Result<()> {
        let req = tonic::Request::new(ReferenceValueRegisterRequest {
            message: message.to_string(),
        });
        let mut client = self.pool.get().await?;
        let _ = client.register_reference_value(req).await?;
        Ok(())
    }

    async fn query_reference_value(&self, reference_value_id: &str) -> Result<Option<Value>> {
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            reference_value_id: reference_value_id.to_string(),
        });
        let mut client = self.pool.get().await?;
        let res = client
            .query_reference_value(req)
            .await?
            .into_inner()
            .reference_value_results;

        match res {
            Some(reference_value) => {
                let reference_value = serde_json::from_str(&reference_value)?;
                Ok(Some(reference_value))
            }
            None => Ok(None),
        }
    }
}

pub struct GrpcManager {
    address: String,
    tls_config: Option<ClientTlsConfig>,
}

#[async_trait::async_trait]
impl Manager for GrpcManager {
    type Connection = ReferenceValueProviderServiceClient<Channel>;
    type Error = anyhow::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        let mut endpoint = Channel::from_shared(self.address.clone())?;
        if let Some(tls) = &self.tls_config {
            endpoint = endpoint.tls_config(tls.clone())?;
        }
        let channel = endpoint.connect().await?;
        Ok(ReferenceValueProviderServiceClient::new(channel))
    }

    async fn check(
        &self,
        conn: Self::Connection,
    ) -> std::result::Result<Self::Connection, Self::Error> {
        Ok(conn)
    }
}
