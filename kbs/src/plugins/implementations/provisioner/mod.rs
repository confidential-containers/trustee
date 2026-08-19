// SPDX-License-Identifier: Apache-2.0

//! Provisioner plugin for KBS.
//!
//! Generates per-VM LUKS encryption keys and stores them in a dedicated
//! storage namespace so that attested guests can retrieve them via
//! `GET /kbs/v0/provisioner/default/{uuid}/root`.
//!
//! The hook sidecar calls `POST /kbs/v0/provisioner/provision` before the VM
//! boots and receives `{uuid, resource_path}` to inject into the VM.
//! On boot the guest attests and fetches the key through the provisioner's
//! own serving endpoint.

use std::collections::HashMap;
use std::sync::Arc;

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};
use key_value_storage::{KeyValueStorageInstance, SetParameters, StorageProvider};
use rand::distr::{Alphanumeric, SampleString};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const PROVISIONER_STORAGE_NAMESPACE: &str = "provisioner";

// UUID v5 namespace for the provisioner plugin.
// Derived from: Uuid::new_v5(&Uuid::NAMESPACE_URL, b"provisioner_plugin")
const PROVISIONER_NAMESPACE: Uuid = uuid::uuid!("feab5599-6854-52bc-95f0-0241c03e620a");

/// Config (deserialized from kbs-config.toml)
#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct ProvisionerConfig {
    /// Length of the random key in bytes (default 32).
    #[serde(default = "default_key_length")]
    pub key_length: usize,
}

fn default_key_length() -> usize {
    32
}

pub struct Provisioner {
    storage: KeyValueStorageInstance,
    key_length: usize,
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
    resource_path: String,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
}

impl Provisioner {
    pub async fn new(
        config: ProvisionerConfig,
        storage_provider: Arc<dyn StorageProvider>,
    ) -> Result<Self> {
        let storage = storage_provider
            .get_or_register(PROVISIONER_STORAGE_NAMESPACE)
            .await
            .context("Provisioner: failed to init storage backend")?;

        Ok(Self {
            storage,
            key_length: config.key_length,
        })
    }
}

impl Provisioner {
    fn generate_random_key(&self) -> String {
        Alphanumeric.sample_string(&mut rand::rng(), self.key_length)
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

    async fn handle_get_resource(
        &self,
        path: &[&str],
        init_data: Option<&serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let resource_key = path.join("/");

        let Some(claims) = init_data else {
            bail!("provisioner requires init_data for resource access");
        };

        let bound_resource = claims
            .get("trustee.kbs.resource")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("init_data missing trustee.kbs.resource"))?;
        let expected = format!("kbs+provisioner:///{resource_key}");
        if bound_resource != expected {
            bail!("init_data resource mismatch: expected {expected}, got {bound_resource}");
        }

        let data = self
            .storage
            .get(&resource_key)
            .await?
            .ok_or_else(|| anyhow!("provisioner resource not found: {resource_key}"))?;
        Ok(data)
    }

    async fn handle_provision(&self, body: &[u8]) -> Result<Vec<u8>> {
        let req: ProvisionRequest = serde_json::from_slice(body).context("invalid JSON body")?;

        let vm_identity = format!("{}/{}", req.namespace, req.vm_name);

        // Generate deterministic UUID from VM identity
        let trustee_uuid = Uuid::new_v5(&PROVISIONER_NAMESPACE, vm_identity.as_bytes()).to_string();

        let resource_path = format!("default/{trustee_uuid}/root");

        if self.storage.get(&resource_path).await?.is_some() {
            let response = ProvisionResponse {
                uuid: trustee_uuid,
                resource_path,
            };
            return Ok(serde_json::to_vec(&response)?);
        };

        let luks_key = self.generate_random_key();

        let confdata_toml = Self::generate_confdata_toml(&luks_key);

        self.storage
            .set(
                &resource_path,
                confdata_toml.as_bytes(),
                SetParameters { overwrite: false },
            )
            .await
            .context("failed to write resource")?;

        let response = ProvisionResponse {
            uuid: trustee_uuid,
            resource_path,
        };

        Ok(serde_json::to_vec(&response)?)
    }

    async fn handle_deprovision(&self, path: &[&str]) -> Result<Vec<u8>> {
        let trustee_uuid = path
            .first()
            .ok_or_else(|| anyhow!("missing uuid in path"))?;
        let resource_path = format!("default/{trustee_uuid}/root");

        let _ = self.storage.delete(&resource_path).await;

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
        init_data: Option<&serde_json::Value>,
        _extensions: &HashMap<String, serde_json::Value>,
    ) -> Result<Vec<u8>> {
        match (method.as_str(), path.first().copied()) {
            ("POST", Some("provision")) => self.handle_provision(body).await,
            ("DELETE", Some("provision")) => self.handle_deprovision(&path[1..]).await,
            ("GET", _) => self.handle_get_resource(path, init_data).await,
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
        match (method.as_str(), path.first().copied()) {
            ("GET", _) => Ok(false),
            _ => Ok(true),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        Ok(method.as_str() == "GET")
    }
}
