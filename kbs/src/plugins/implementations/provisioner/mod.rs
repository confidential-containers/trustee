// SPDX-License-Identifier: Apache-2.0

//! Provisioner plugin for KBS.
//!
//! Generates per-VM LUKS encryption keys and stores them in a dedicated
//! storage namespace so that attested guests can retrieve them via
//! `GET /kbs/v0/provisioner/default/{uuid}/root`.
//!
//! The hook sidecar calls `POST /kbs/v0/provisioner/provision` before the VM
//! boots and receives `{uuid, oemstring, mrconfigid}` to inject into SMBIOS.
//! On boot the guest attests and fetches the key through the provisioner's
//! own serving endpoint.

use std::collections::HashMap;

use actix_web::http::Method;
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use key_value_storage::{KeyValueStorageInstance, SetParameters, StorageBackendConfig};
use rand::distributions::{Alphanumeric, DistString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use uuid::Uuid;

const PROVISIONER_STORAGE_NAMESPACE: &str = "provisioner";

// Config (deserialized from kbs-config.toml)
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct ProvisionerConfig {
    /// URL that will be embedded in `initdata.toml` for the guest.
    pub kbs_url: String,

    /// Length of the random LUKS key in bytes (default 32).
    #[serde(default = "default_key_length")]
    pub key_length: usize,
}

fn default_key_length() -> usize {
    32
}

pub struct Provisioner {
    storage: KeyValueStorageInstance,
    kbs_url: String,
    key_length: usize,
    // TODO: This in-memory cache grows unboundedly.
    // More critically, the cache does not survive KBS restarts:
    // if the sidecar re-provisions the same VM after a restart,
    // a new UUID/key pair is generated, replacing the original resource.
    // The VM's LUKS volume would then fail to unlock
    // because the key no longer matches. The cache (or the vm->resource
    // mapping) must be persisted to the storage backend so it can be
    // restored on startup.
    cache: tokio::sync::RwLock<HashMap<String, ProvisionResponse>>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ProvisionRequest {
    vm_name: String,
    #[serde(default = "default_namespace")]
    namespace: String,
}

fn default_namespace() -> String {
    "default".into()
}

#[derive(Serialize, Clone)]
struct ProvisionResponse {
    uuid: String,
    oemstring: String,
    mrconfigid: String,
    resource_path: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
}

impl Provisioner {
    pub async fn new(
        config: ProvisionerConfig,
        storage_backend_config: &StorageBackendConfig,
    ) -> Result<Self> {
        let storage = storage_backend_config
            .backends
            .to_client_with_namespace(
                storage_backend_config.storage_type,
                PROVISIONER_STORAGE_NAMESPACE,
            )
            .await
            .map_err(|e| anyhow!("Provisioner: failed to init storage backend: {e}"))?;

        Ok(Self {
            storage,
            kbs_url: config.kbs_url,
            key_length: config.key_length,
            cache: tokio::sync::RwLock::new(HashMap::new()),
        })
    }
}

impl Provisioner {
    fn generate_random_key(&self) -> String {
        let key = Alphanumeric.sample_string(&mut rand::thread_rng(), self.key_length);
        key
    }

    // This init-data is not meant to be compatible with CoCo.
    fn generate_initdata_toml(&self, resource_path: &str) -> String {
        format!(
            "algorithm = \"sha384\"\n\
             version = \"0.1.0\"\n\
             \n\
             [data]\n\
             \"trustee.kbs.url\" = \"{}\"\n\
             \"trustee.kbs.resource\" = \"kbs+provisioner:///{}\"\n",
            self.kbs_url, resource_path
        )
    }

    fn generate_confdata_toml(luks_key: &str) -> String {
        format!(
            "version = \"0.1.0\"\n\
             \n\
             [data]\n\
             \"io.cryptsetup.key.text.root\" = \"{}\"\n",
            luks_key
        )
    }

    async fn handle_get_resource(&self, path: &[&str]) -> Result<Vec<u8>> {
        let resource_key = path.join("/");
        let data = self
            .storage
            .get(&resource_key)
            .await?
            .ok_or_else(|| anyhow!("provisioner resource not found: {resource_key}"))?;
        Ok(data)
    }

    async fn handle_provision(&self, body: &[u8]) -> Result<Vec<u8>> {
        let req: ProvisionRequest =
            serde_json::from_slice(body).map_err(|e| anyhow!("invalid JSON body: {e}"))?;

        let cache_key = format!("{}/{}", req.namespace, req.vm_name);

        // Return cached result if already provisioned
        if let Some(cached) = self.cache.read().await.get(&cache_key) {
            return Ok(serde_json::to_vec(cached)?);
        }

        // TODO: UUIDv4 is random but not tied to VM identity. A more robust
        // approach would derive the UUID deterministically from the VM's
        // attributes (e.g. name + namespace + cluster ID) to ensure
        // idempotency and traceability across re-provisions.
        // A uniqueness check against existing storage entries should also
        // be added to avoid collisions before writing the resource.
        let trustee_uuid = Uuid::new_v4().to_string();
        let resource_path = format!("default/{trustee_uuid}/root");
        let luks_key = self.generate_random_key();

        let initdata_toml = self.generate_initdata_toml(&resource_path);
        let confdata_toml = Self::generate_confdata_toml(&luks_key);

        let oemstring = B64.encode(initdata_toml.as_bytes());
        let mrconfigid = {
            let digest = Sha384::digest(initdata_toml.as_bytes());
            B64.encode(digest)
        };

        // Write the confdata (LUKS key) to the provisioner's own storage namespace.
        // TODO: Using overwrite: true could silently replace another VM's key
        // on UUID collision. Use overwrite: false and handle the conflict error,
        // or check existence before writing.
        self.storage
            .set(
                &resource_path,
                confdata_toml.as_bytes(),
                SetParameters { overwrite: false },
            )
            .await
            .map_err(|e| anyhow!("failed to write resource: {e}"))?;

        // NOTE: The sidecar currently only consumes `oemstring` and `mrconfigid`.
        // `uuid` and `resource_path` are included for debugging/deprovision but
        // are redundant for the sidecar since `oemstring` (base64 of initdata.toml)
        // already embeds the resource_path.
        let response = ProvisionResponse {
            uuid: trustee_uuid,
            oemstring,
            mrconfigid,
            resource_path,
        };

        self.cache.write().await.insert(cache_key, response.clone());

        Ok(serde_json::to_vec(&response)?)
    }

    async fn handle_deprovision(&self, path: &[&str]) -> Result<Vec<u8>> {
        let trustee_uuid = path
            .first()
            .ok_or_else(|| anyhow!("missing uuid in path"))?;
        let resource_path = format!("default/{trustee_uuid}/root");

        let _ = self.storage.delete(&resource_path).await;

        // Remove from cache
        self.cache
            .write()
            .await
            .retain(|_, v| v.uuid != *trustee_uuid);

        Ok(serde_json::to_vec(&StatusResponse {
            status: "deleted".into(),
        })?)
    }
}

#[async_trait::async_trait]
impl super::super::plugin_manager::ClientPlugin for Provisioner {
    async fn handle(
        &self,
        body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        match (method.as_str(), path.first().copied()) {
            ("POST", Some("provision")) => self.handle_provision(body).await,
            ("DELETE", Some("provision")) => self.handle_deprovision(&path[1..]).await,
            ("GET", _) => self.handle_get_resource(path).await,
            _ => bail!(
                "unsupported: {} /kbs/v0/provisioner/{}",
                method,
                path.join("/")
            ),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        // GET: guest fetches the resource after TEE attestation (validate_auth = false).
        // POST/DELETE: sidecar provisions/deprovisions via admin auth (validate_auth = true).
        //
        // NOTE: Currently relies on InsecureAllowAll admin backend for dev.
        // For production, switch to Simple admin with JWT-signed requests
        // and scoped roles, e.g.:
        //   [admin] type = "Simple"
        //   [[admin.personas]] id = "provisioner" public_key_path = "..."
        //   [[admin.roles]] id = "provisioner" allowed_endpoints = "^/kbs/v0/provisioner/.*$"
        match (method.as_str(), path.first().copied()) {
            ("GET", _) => Ok(false),
            _ => Ok(true),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        Ok(method.as_str() == "GET")
    }
}
