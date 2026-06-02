use std::time::Duration;

use mobc::{Manager, Pool};
use serde::Deserialize;
use serde_json::Value;
use tonic::transport::Channel;
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
}

fn default_address() -> String {
    "127.0.0.1:50003".into()
}

/// The default pool size for the RVPS client.
const DEFAULT_RVPS_POOL_SIZE: u64 = 10;

/// Drop and re-establish a pooled connection once it has been idle for this
/// long, so a connection that died silently while idle is recycled instead of
/// being handed out to the next query.
const RVPS_CONN_MAX_IDLE_LIFETIME: Duration = Duration::from_secs(30);

/// Send an HTTP/2 keep-alive ping after this much inactivity on a pooled
/// connection, so a broken connection is noticed promptly rather than on the
/// next (possibly much later) query.
const RVPS_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// How long to wait for a keep-alive ping acknowledgement before treating the
/// connection as dead.
const RVPS_KEEP_ALIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Time budget for the on-checkout connection health probe. It runs on every
/// pool.get() and only needs a local round-trip to RVPS, so it is kept short.
const RVPS_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(1);

/// Placeholder reference-value key used to probe connection liveness. RVPS
/// returns Ok(None) for an unknown key, which confirms the connection is live
/// without triggering an "Is a directory" error that would otherwise force an
/// unnecessary reconnect on every pool.get() call.
const RVPS_HEALTH_CHECK_KEY: &str = "__healthcheck__";

pub struct Agent {
    pool: Pool<GrpcManager>,
}

impl Agent {
    pub async fn new(addr: &str) -> Result<Self> {
        info!(
            "connect to remote RVPS [{}] with pool size {}",
            addr, DEFAULT_RVPS_POOL_SIZE
        );

        let mut address = addr.to_string();
        if !address.starts_with("http://") && !address.starts_with("https://") {
            debug!("add http:// prefix to the rvps grpc address [{}]", address);
            address = format!("http://{}", address);
        }

        let manager = GrpcManager { address };
        let pool = Pool::builder()
            .max_open(DEFAULT_RVPS_POOL_SIZE)
            .max_idle_lifetime(Some(RVPS_CONN_MAX_IDLE_LIFETIME))
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
}

#[async_trait::async_trait]
impl Manager for GrpcManager {
    type Connection = ReferenceValueProviderServiceClient<Channel>;
    type Error = anyhow::Error;

    async fn connect(&self) -> std::result::Result<Self::Connection, Self::Error> {
        // Called for the initial connection and whenever the pool replaces a
        // connection that failed check() below, so this is the single place
        // that observes every (re)connection to RVPS.
        debug!("establishing RVPS gRPC connection to {}", self.address);
        let channel = Channel::from_shared(self.address.clone())?
            .keep_alive_while_idle(true)
            .http2_keep_alive_interval(RVPS_KEEP_ALIVE_INTERVAL)
            .keep_alive_timeout(RVPS_KEEP_ALIVE_TIMEOUT)
            .connect()
            .await?;
        Ok(ReferenceValueProviderServiceClient::new(channel))
    }

    async fn check(
        &self,
        conn: Self::Connection,
    ) -> std::result::Result<Self::Connection, Self::Error> {
        let mut c = conn;
        let req = tonic::Request::new(ReferenceValueQueryRequest {
            reference_value_id: RVPS_HEALTH_CHECK_KEY.to_string(),
        });
        // We only report whether the connection is still usable; the pool is
        // responsible for discarding it and calling connect() to replace it.
        match tokio::time::timeout(RVPS_HEALTH_CHECK_TIMEOUT, c.query_reference_value(req)).await {
            Ok(Ok(_)) => Ok(c),
            Ok(Err(e)) => Err(anyhow::anyhow!("stale connection: {e}")),
            Err(_) => Err(anyhow::anyhow!("RVPS health check timed out")),
        }
    }
}
