// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fmt::Display, sync::Arc};

use actix_web::http::Method;
use anyhow::{Context, Result};
use key_value_storage::StorageBackendConfig;
use serde::Deserialize;

use super::{sample, RepositoryConfig, ResourceStorage};

#[cfg(feature = "nebula-ca-plugin")]
use super::{NebulaCaPlugin, NebulaCaPluginConfig};

#[cfg(feature = "pkcs11")]
use super::{Pkcs11Backend, Pkcs11Config};

type ClientPluginInstance = Arc<dyn ClientPlugin>;

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
        }
    }
}

impl PluginsConfig {
    /// Turn the PluginsConfig into a concrete plugin instance
    /// If the plugin instance needs a backend storage, the storage_backend can be used.
    pub async fn into_client_plugin_instance(
        self,
        storage_backend_config: &StorageBackendConfig,
    ) -> Result<ClientPluginInstance> {
        let plugin = match self {
            PluginsConfig::Sample(cfg) => {
                let sample_plugin =
                    sample::Sample::try_from(cfg).context("Initialize 'Sample' plugin failed")?;
                Arc::new(sample_plugin) as _
            }
            PluginsConfig::ResourceStorage(repository_config) => {
                let resource_storage =
                    ResourceStorage::new(repository_config, storage_backend_config)
                        .await
                        .context("Initialize 'Resource' plugin failed")?;
                Arc::new(resource_storage) as _
            }
            #[cfg(feature = "nebula-ca-plugin")]
            PluginsConfig::NebulaCaPlugin(nebula_ca_config) => {
                let nebula_ca = NebulaCaPlugin::try_from(nebula_ca_config)
                    .context("Initialize 'nebula-ca-plugin' failed")?;
                Arc::new(nebula_ca) as _
            }
            #[cfg(feature = "pkcs11")]
            PluginsConfig::Pkcs11(pkcs11_config) => {
                let pkcs11 = Pkcs11Backend::try_from(pkcs11_config)
                    .context("Initialize 'pkcs11' plugin failed")?;
                Arc::new(pkcs11) as _
            }
        };

        Ok(plugin)
    }
}

/// [`PluginManager`] manages different kinds of plugins.
#[derive(Clone)]
pub struct PluginManager {
    plugins: HashMap<String, ClientPluginInstance>,
}

impl PluginManager {
    /// Turn the PluginsConfig into a concrete plugin instance
    /// If the plugin instance needs a backend storage, the storage_type and storage_config can be used.
    pub async fn new(
        value: Vec<PluginsConfig>,
        storage_backend_config: &StorageBackendConfig,
    ) -> Result<Self> {
        let mut plugins = HashMap::new();
        for cfg in value {
            let name = cfg.to_string();
            let plugin: ClientPluginInstance = cfg
                .into_client_plugin_instance(storage_backend_config)
                .await?;
            plugins.insert(name, plugin);
        }
        Ok(Self { plugins })
    }
}

impl PluginManager {
    pub fn get(&self, name: &str) -> Option<ClientPluginInstance> {
        self.plugins.get(name).cloned()
    }
}
