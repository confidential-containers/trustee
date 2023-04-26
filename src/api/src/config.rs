// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::resource::RepositoryType;
use anyhow::anyhow;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::path::Path;

/// KBS Config
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// Resource repository type
    pub repository_type: RepositoryType,

    /// OPIONAL
    /// Resource repository description
    /// This is a JSON string,
    /// Various to repository type.
    pub repository_description: Option<Value>,

    /// OPTIONAL
    /// Remote Attestation Service address.
    /// Only used in remote AS mode.
    /// If Null, default remote AS addr will be used.
    pub as_addr: Option<String>,

    /// OPTIONAL
    /// Native Attestation Service config file path
    /// Only used with the built-in CoCo AS.
    /// If Null, default AS config will be used.
    pub as_config_file_path: Option<String>,
}

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            repository_type: RepositoryType::LocalFs,
            repository_description: None,
            as_addr: None,
            as_config_file_path: None,
        }
    }
}

impl TryFrom<&Path> for Config {
    /// Load `Config` from a JSON configuration file like:
    ///    {
    ///        "repository_type": "LocalFs",
    ///        "repository_description": {
    ///            "dir_path": "/opt/confidential-containers/kbs/repository"
    ///        },
    ///        # Only used in Remote Attestation-Service mode
    ///        "as_addr": "http://127.0.0.1:50004",
    ///        # Only used in Native Attestation-Service mode
    ///        "as_config_file_path": "/etc/as-config.json"
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path)
            .map_err(|e| anyhow!("failed to open KBS config file {}", e.to_string()))?;

        serde_json::from_reader::<File, Config>(file)
            .map_err(|e| anyhow!("failed to parse KBS config file {}", e.to_string()))
    }
}
