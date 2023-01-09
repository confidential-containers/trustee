// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::resource::RepositoryType;
use anyhow::anyhow;
use serde::Deserialize;
use std::fs::File;
use std::path::Path;

/// KBS Config
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Resource repository type
    pub repository_type: RepositoryType,

    /// Resource repository description
    /// This is a JSON string,
    /// Various to repository type.
    #[serde(default)]
    pub repository_description: Option<String>,
}

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            repository_type: RepositoryType::LocalFs,
            repository_description: None,
        }
    }
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a configuration file like:
    ///    {
    ///        "repository_type": "LocalFs",
    ///        "repository_description": {
    ///            "dir_path": file:///opt/confidential-containers/kbs/repository"
    ///        }
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path)
            .map_err(|e| anyhow!("failed to open KBS config file {}", e.to_string()))?;

        serde_json::from_reader::<File, Config>(file)
            .map_err(|e| anyhow!("failed to parse AS config file {}", e.to_string()))
    }
}
