// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::Arc,
};

use actix_web::http::Method;
use anyhow::{Context, Result};
use key_value_storage::StorageBackendConfig;
use serde::Deserialize;

#[cfg(feature = "external-plugin")]
use {
    super::implementations::external_plugin::{GrpcPluginProxy, RESERVED_PLUGIN_NAMES},
    super::implementations::ExternalPluginConfig,
    tracing::warn,
};

use super::{sample, RepositoryConfig, ResourceStorage};

#[cfg(feature = "nebula-ca-plugin")]
use super::{NebulaCaPlugin, NebulaCaPluginConfig};

#[cfg(feature = "pkcs11")]
use super::{Pkcs11Backend, Pkcs11Config};

/// Request context forwarded to plugins via gRPC metadata.
///
/// Provides session, TEE, and attestation information so that plugins
/// can make authorization decisions and produce audit logs without
/// receiving raw tokens (trust boundary preserved by omission).
#[derive(Clone, Debug, Default)]
pub struct PluginContext {
    /// Session ID from KBS session cookie (if available)
    pub session_id: Option<String>,
    /// TEE type from attestation request (if attested)
    pub tee_type: Option<String>,
    /// Whether the request is from an attested session
    pub is_attested: bool,
}

/// Return type from a plugin handler, carrying body plus optional HTTP hints.
///
/// External plugins can influence the HTTP response status code and content type.
/// Built-in plugins return `None` for both hints, which KBS resolves to 200/text/xml.
pub struct PluginOutput {
    pub body: Vec<u8>,
    /// HTTP status code. `None` → KBS default (200 OK).
    pub status_code: Option<u16>,
    /// Content-Type header value. `None` → KBS default ("text/xml").
    pub content_type: Option<String>,
}

impl std::fmt::Debug for PluginOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginOutput")
            .field("body", &format!("<{} bytes redacted>", self.body.len()))
            .field("status_code", &self.status_code)
            .field("content_type", &self.content_type)
            .finish()
    }
}

impl From<Vec<u8>> for PluginOutput {
    fn from(body: Vec<u8>) -> Self {
        Self {
            body,
            status_code: None,
            content_type: None,
        }
    }
}

/// Typed enum for plugin dispatch.
///
/// Built-in plugins are stored as `Arc<dyn ClientPlugin>` and dispatched with
/// the original `handle()` signature (no context, returns `Vec<u8>`).
///
/// External gRPC plugins are stored directly as `Arc<GrpcPluginProxy>` and
/// dispatched via `handle_with_context()`, which injects session/TEE metadata
/// into gRPC request headers.
#[derive(Clone)]
pub(crate) enum PluginInstance {
    BuiltIn(Arc<dyn ClientPlugin>),
    #[cfg(feature = "external-plugin")]
    External(Arc<GrpcPluginProxy>),
}

impl std::fmt::Debug for PluginInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginInstance::BuiltIn(_) => write!(f, "PluginInstance::BuiltIn(...)"),
            #[cfg(feature = "external-plugin")]
            PluginInstance::External(p) => write!(f, "PluginInstance::External({:?})", p),
        }
    }
}

impl PluginInstance {
    pub async fn validate_auth(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        match self {
            PluginInstance::BuiltIn(p) => p.validate_auth(body, query, path, method).await,
            #[cfg(feature = "external-plugin")]
            PluginInstance::External(p) => p.validate_auth(body, query, path, method).await,
        }
    }

    pub async fn dispatch(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        _ctx: &PluginContext,
    ) -> Result<PluginOutput> {
        match self {
            PluginInstance::BuiltIn(p) => {
                let bytes = p.handle(body, query, path, method).await?;
                Ok(PluginOutput {
                    body: bytes,
                    status_code: None,
                    content_type: None,
                })
            }
            #[cfg(feature = "external-plugin")]
            PluginInstance::External(p) => {
                p.handle_with_context(body, query, path, method, _ctx).await
            }
        }
    }

    pub async fn encrypted(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        match self {
            PluginInstance::BuiltIn(p) => p.encrypted(body, query, path, method).await,
            #[cfg(feature = "external-plugin")]
            PluginInstance::External(p) => p.encrypted(body, query, path, method).await,
        }
    }
}

#[async_trait::async_trait]
pub trait ClientPlugin: Send + Sync {
    /// This function is the entry to a client plugin. The function
    /// marks `&self` rather than `&mut self`, because it will leave
    /// state and synchronization issues down to the concrete plugin.
    ///
    /// TODO: change body from Vec slice into Reader to apply for large
    /// body stream.
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>>;

    /// Whether the concrete request needs to validate the admin auth.
    /// If returns `Ok(true)`, the KBS server will perform an admin auth
    /// validation before handle the request.
    async fn validate_auth(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool>;

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<bool>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "name")]
pub enum PluginsConfig {
    #[serde(alias = "sample")]
    Sample(sample::SampleConfig),

    #[serde(alias = "resource")]
    ResourceStorage(RepositoryConfig),

    #[cfg(feature = "nebula-ca-plugin")]
    #[serde(alias = "nebula-ca")]
    NebulaCaPlugin(NebulaCaPluginConfig),

    #[cfg(feature = "pkcs11")]
    #[serde(alias = "pkcs11")]
    Pkcs11(Pkcs11Config),

    #[cfg(feature = "external-plugin")]
    #[serde(alias = "external")]
    ExternalPlugin(ExternalPluginConfig),
}

impl Display for PluginsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginsConfig::Sample(_) => f.write_str("sample"),
            PluginsConfig::ResourceStorage(_) => f.write_str("resource"),
            #[cfg(feature = "nebula-ca-plugin")]
            PluginsConfig::NebulaCaPlugin(_) => f.write_str("nebula-ca"),
            #[cfg(feature = "pkcs11")]
            PluginsConfig::Pkcs11(_) => f.write_str("pkcs11"),
            #[cfg(feature = "external-plugin")]
            PluginsConfig::ExternalPlugin(cfg) => f.write_str(&cfg.plugin_name),
        }
    }
}

/// [`PluginManager`] manages different kinds of plugins.
#[derive(Clone)]
pub struct PluginManager {
    plugins: HashMap<String, PluginInstance>,
}

impl std::fmt::Debug for PluginManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginManager")
            .field("plugins", &self.plugins.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl PluginManager {
    /// Initialize plugin manager with async support for external gRPC plugins.
    ///
    /// Uses async initialization to avoid blocking the single-threaded actix runtime
    /// when connecting to external plugin gRPC servers.
    pub async fn new(
        value: Vec<PluginsConfig>,
        storage_backend_config: &StorageBackendConfig,
    ) -> Result<Self> {
        let mut seen_names = HashSet::new();
        let mut plugins = HashMap::new();

        for cfg in value {
            let name = cfg.to_string();

            // Check for name collision
            if !seen_names.insert(name.clone()) {
                anyhow::bail!(
                    "Plugin name collision detected: '{}' is already registered. \
                     Each plugin must have a unique name.",
                    name
                );
            }

            let instance: PluginInstance = match cfg {
                #[cfg(feature = "external-plugin")]
                PluginsConfig::ExternalPlugin(ext_cfg) => {
                    // Reject names that collide with built-in KBS endpoints
                    if RESERVED_PLUGIN_NAMES.contains(&ext_cfg.plugin_name.as_str()) {
                        anyhow::bail!(
                            "Plugin name '{}' conflicts with a built-in KBS endpoint. \
                             Reserved names: {:?}",
                            ext_cfg.plugin_name,
                            RESERVED_PLUGIN_NAMES
                        );
                    }

                    // Validate TLS configuration before attempting connection
                    ext_cfg
                        .validate_tls_config()
                        .context("Invalid TLS configuration")?;

                    // Log warning for insecure mode
                    if ext_cfg.tls_mode.is_insecure() {
                        warn!(
                            "External plugin '{}' configured with insecure mode (plaintext). \
                             This is ONLY safe for development. Never use in production.",
                            ext_cfg.plugin_name
                        );
                    }

                    let proxy = GrpcPluginProxy::new(ext_cfg)
                        .await
                        .context("Initialize external gRPC plugin failed")?;
                    PluginInstance::External(Arc::new(proxy))
                }
                // Built-in plugins are initialised synchronously.
                //
                // Each variant is matched explicitly rather than using a
                // catch-all `other => other.try_into()?` pattern. The explicit
                // match keeps construction in one place and lets the compiler
                // enforce exhaustiveness — if a new variant is added to
                // PluginsConfig without a corresponding arm here, the build
                // fails immediately rather than producing a runtime panic.
                PluginsConfig::Sample(cfg) => PluginInstance::BuiltIn(Arc::new(
                    sample::Sample::try_from(cfg).context("Initialize 'Sample' plugin failed")?,
                )),
                PluginsConfig::ResourceStorage(cfg) => PluginInstance::BuiltIn(Arc::new(
                    ResourceStorage::new(cfg, storage_backend_config)
                        .await
                        .context("Initialize 'Resource' plugin failed")?,
                )),
                #[cfg(feature = "nebula-ca-plugin")]
                PluginsConfig::NebulaCaPlugin(cfg) => PluginInstance::BuiltIn(Arc::new(
                    NebulaCaPlugin::try_from(cfg)
                        .context("Initialize 'nebula-ca-plugin' failed")?,
                )),
                #[cfg(feature = "pkcs11")]
                PluginsConfig::Pkcs11(cfg) => PluginInstance::BuiltIn(Arc::new(
                    Pkcs11Backend::try_from(cfg).context("Initialize 'pkcs11' plugin failed")?,
                )),
            };

            plugins.insert(name, instance);
        }

        Ok(Self { plugins })
    }
}

impl PluginManager {
    pub(crate) fn get(&self, name: &str) -> Option<PluginInstance> {
        self.plugins.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use key_value_storage::StorageBackendConfig;

    use super::*;
    use crate::plugins::implementations::sample::SampleConfig;

    /// Two Sample entries with the same effective name should be rejected with a
    /// "collision" / "already registered" error.
    #[tokio::test]
    async fn duplicate_plugin_name_is_rejected() {
        let configs = vec![
            PluginsConfig::Sample(SampleConfig {
                item: "first".to_string(),
            }),
            PluginsConfig::Sample(SampleConfig {
                item: "second".to_string(),
            }),
        ];
        let storage = StorageBackendConfig::default();

        let err = PluginManager::new(configs, &storage)
            .await
            .expect_err("expected duplicate-name error");

        let msg = err.to_string();
        assert!(
            msg.contains("collision") || msg.contains("already registered"),
            "unexpected error message: {msg}"
        );
    }

    /// External plugins whose name matches a built-in KBS route prefix must be
    /// rejected before any gRPC connection attempt.
    #[cfg(feature = "external-plugin")]
    #[tokio::test]
    async fn reserved_plugin_name_auth_is_rejected() {
        use crate::plugins::implementations::external_plugin::{ExternalPluginConfig, TlsMode};

        let configs = vec![PluginsConfig::ExternalPlugin(ExternalPluginConfig {
            plugin_name: "auth".to_string(),
            endpoint: "http://localhost:50099".to_string(),
            timeout_ms: None,
            tls_mode: TlsMode::Insecure,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        })];

        let storage = StorageBackendConfig::default();
        let err = PluginManager::new(configs, &storage)
            .await
            .expect_err("expected reserved-name error");

        let msg = err.to_string();
        assert!(
            msg.contains("conflicts with a built-in KBS endpoint") || msg.contains("Reserved"),
            "unexpected error message: {msg}"
        );
    }

    /// Same check for another reserved name: "attest".
    #[cfg(feature = "external-plugin")]
    #[tokio::test]
    async fn reserved_plugin_name_attest_is_rejected() {
        use crate::plugins::implementations::external_plugin::{ExternalPluginConfig, TlsMode};

        let configs = vec![PluginsConfig::ExternalPlugin(ExternalPluginConfig {
            plugin_name: "attest".to_string(),
            endpoint: "http://localhost:50099".to_string(),
            timeout_ms: None,
            tls_mode: TlsMode::Insecure,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        })];

        let storage = StorageBackendConfig::default();
        let err = PluginManager::new(configs, &storage)
            .await
            .expect_err("expected reserved-name error");

        let msg = err.to_string();
        assert!(
            msg.contains("conflicts with a built-in KBS endpoint") || msg.contains("Reserved"),
            "unexpected error message: {msg}"
        );
    }

    /// A non-reserved external plugin name should pass the name guard.
    /// It will ultimately fail when trying to connect to a non-existent gRPC
    /// server, but the error must NOT mention "conflicts with" or "Reserved".
    #[cfg(feature = "external-plugin")]
    #[tokio::test]
    async fn non_reserved_plugin_name_passes_name_guard() {
        use crate::plugins::implementations::external_plugin::{ExternalPluginConfig, TlsMode};

        let configs = vec![PluginsConfig::ExternalPlugin(ExternalPluginConfig {
            plugin_name: "my-plugin".to_string(),
            endpoint: "http://localhost:50099".to_string(),
            timeout_ms: None,
            tls_mode: TlsMode::Insecure,
            ca_cert_path: None,
            client_cert_path: None,
            client_key_path: None,
        })];

        // This will fail because no gRPC server is listening, but the error
        // must be about connection, not about the name being reserved.
        let storage = StorageBackendConfig::default();
        let err = PluginManager::new(configs, &storage)
            .await
            .expect_err("expected a connection error (no gRPC server running)");

        let msg = err.to_string();
        assert!(
            !msg.contains("conflicts with"),
            "name guard should have passed but got: {msg}"
        );
        assert!(
            !msg.contains("Reserved"),
            "name guard should have passed but got: {msg}"
        );
    }
}
