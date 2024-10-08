// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

use super::ResourceError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Failed to initialize plugin {name}")]
    InitializePluginFailed {
        #[source]
        source: anyhow::Error,
        name: &'static str,
    },

    #[error("Plugin Manager Initialization failed")]
    PluginManagerInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Error happens to plugin {plugin_name}")]
    PluginHandlerError {
        #[source]
        source: anyhow::Error,
        plugin_name: String,
    },

    #[error("Resource access failed")]
    ResourceAccessFailed(#[from] ResourceError),
}
