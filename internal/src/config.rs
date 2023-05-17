// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use resource::RepositoryType;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::path::Path;
use token::AttestationTokenBrokerType;

/// KBS Config
#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    /// The resource repository type.
    ///
    /// Possible values:
    /// * `LocalFs` for locally stored resources.
    pub repository_type: RepositoryType,

    /// Resource repository description (Optional).
    ///
    /// This is a JSON string describing the repository configuration.
    /// The JSON string schema is repository type specific.
    pub repository_description: Option<Value>,

    /// The Attestation Token Result Broker type.
    ///
    /// Possible values:
    /// * `Simple`
    pub attestation_token_type: AttestationTokenBrokerType,

    /// The Remote Attestation Service API address (Optional).
    ///
    /// This is only relevant when running the Confidential Containers
    /// Attestation Service through a gRPC socket.
    /// If empty, the default remote AS address is used.
    pub as_addr: Option<String>,

    /// The built-in Attestation Service configuration file path (Optional).
    ///
    /// This is only relevant when running the Confidential Containers
    /// Attestation Service as a built-in crate.
    /// If empty, the default AS configuration file path is used.
    pub as_config_file_path: Option<String>,
}

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            repository_type: RepositoryType::LocalFs,
            repository_description: None,
            attestation_token_type: AttestationTokenBrokerType::Simple,
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
    ///            "attestation_token_type": "Simple",
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
