// Copyright (c) 2024 by IBM Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "nebula-plugin")]
mod nebula;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

#[cfg(feature = "nebula-plugin")]
use crate::resource::plugin::nebula::NebulaPluginConfig;

trait PluginBuild {
    fn get_plugin_name(&self) -> &str;
    fn create_plugin(&self, work_dir: &str) -> Result<Arc<RwLock<dyn Plugin + Send + Sync>>>;
}

#[derive(Clone, Debug, Default, Deserialize)]
pub struct PluginManagerConfig {
    work_dir: String,
    enabled_plugins: Vec<String>,
}

impl PluginManagerConfig {
    fn get_plugin_builders(&self) -> Vec<Box<dyn PluginBuild>> {
        #[allow(unused_mut)]
        let mut p: Vec<Box<dyn PluginBuild>> = Vec::new();

        // List of all plugins supported
        #[cfg(feature = "nebula-plugin")]
        p.push(Box::new(NebulaPluginConfig::default()));

        p
    }

    pub fn create_plugin_manager(&self) -> Result<Arc<RwLock<PluginManager>>> {
        if !Path::new(&self.work_dir).exists() {
            fs::create_dir_all(&self.work_dir)
                .with_context(|| "Create resource plugin dir".to_string())?;
        }

        #[allow(unused_mut)]
        let mut manager = PluginManager {
            plugins: Vec::new(),
        };

        let plugin_builders = self.get_plugin_builders();

        for plugin_name in self.enabled_plugins.iter() {
            let builder = plugin_builders
                .iter()
                .find(|x| x.get_plugin_name() == plugin_name)
                .ok_or(anyhow!(
                    "Cargo {}-plugin feature is either not set or not supported",
                    plugin_name,
                ))?;

            let plugin_dir = format!("{}/{}", self.work_dir, builder.get_plugin_name());
            let plugin = builder.create_plugin(plugin_dir.as_str())?;
            manager.plugins.push(plugin);

            log::info!("{} plugin loaded", builder.get_plugin_name());
        }

        log::info!("{} plugin(s) loaded", manager.plugins.len());

        Ok(Arc::new(RwLock::new(manager)))
    }
}

#[async_trait::async_trait]
trait Plugin {
    async fn get_name(&self) -> &str;
    async fn get_resource(&self, resource: &str, query_string: &str) -> Result<Vec<u8>>;
}

pub struct PluginManager {
    plugins: Vec<Arc<RwLock<dyn Plugin + Send + Sync>>>,
}

impl PluginManager {
    pub async fn get_resource(
        &self,
        plugin_name: &str,
        resource: &str,
        query_string: &str,
    ) -> Result<Vec<u8>> {
        for plugin in self.plugins.iter() {
            let p = plugin.read().await;

            if *plugin_name == *p.get_name().await {
                return p.get_resource(resource, query_string).await;
            }
        }
        bail!("Plugin {} not found", plugin_name)
    }
}
