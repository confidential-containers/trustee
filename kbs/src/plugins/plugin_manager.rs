// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fmt::Display, sync::Arc};

use actix_web::{http::Method, HttpResponse};
use serde::Deserialize;

use super::{sample, Error, Result};

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
        body: Vec<u8>,
        query: String,
        path: String,
        method: &Method,
    ) -> Result<HttpResponse>;
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "name")]
pub enum PluginsConfig {
    #[serde(alias = "sample")]
    Sample(sample::SampleConfig),
}

impl Display for PluginsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PluginsConfig::Sample(_) => f.write_str("sample"),
        }
    }
}

impl TryInto<ClientPluginInstance> for PluginsConfig {
    type Error = Error;

    fn try_into(self) -> Result<ClientPluginInstance> {
        let plugin = match self {
            PluginsConfig::Sample(cfg) => {
                let sample_plugin =
                    sample::Sample::try_from(cfg).map_err(|e| Error::InitializePluginFailed {
                        source: e,
                        name: "Sample",
                    })?;
                Arc::new(sample_plugin)
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

impl TryFrom<Vec<PluginsConfig>> for PluginManager {
    type Error = Error;

    fn try_from(value: Vec<PluginsConfig>) -> Result<Self> {
        let plugins = value
            .into_iter()
            .map(|cfg| {
                let name = cfg.to_string();
                let plugin: ClientPluginInstance = cfg.try_into()?;
                Ok((name, plugin))
            })
            .collect::<Result<HashMap<String, ClientPluginInstance>>>()?;
        Ok(Self { plugins })
    }
}

impl PluginManager {
    pub fn get(&self, name: &str) -> Option<ClientPluginInstance> {
        self.plugins.get(name).cloned()
    }
}
