// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "amber-as")]
use crate::attestation::amber::AmberConfig;
use crate::resource::RepositoryType;
use crate::token::AttestationTokenVerifierType;
use anyhow::anyhow;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::path::Path;

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

    /// The Attestation Token type.
    ///
    /// Possible values:
    /// * `CoCo`
    pub attestation_token_type: AttestationTokenVerifierType,

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

    /// OPTIONAL
    /// Amber Attestation Service configuration.
    /// Only used in Amber AS mode.
    #[cfg(feature = "amber-as")]
    pub amber: Option<AmberConfig>,
}

impl Default for Config {
    // Construct a default instance of `Config`
    fn default() -> Config {
        Config {
            repository_type: RepositoryType::LocalFs,
            repository_description: None,
            attestation_token_type: AttestationTokenVerifierType::CoCo,
            as_addr: None,
            as_config_file_path: None,
            #[cfg(feature = "amber-as")]
            amber: None,
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
    ///            "attestation_token_type": "CoCo",
    ///        # Only used in Remote Attestation-Service mode
    ///        "as_addr": "http://127.0.0.1:50004",
    ///        # Only used in Native Attestation-Service mode
    ///        "as_config_file_path": "/etc/as-config.json",
    ///        # Only used in Amber Attestation-Service mode
    ///        "amber" : {
    ///            "base_url": "https://amber.com",
    ///            "api_key": "tBfd5kKX2x9ahbodKV1...",
    ///            "certs_file": "/etc/amber/amber-certs.txt",
    ///            # Optional, default is false.
    ///            "allow_unmatched_policy": true
    ///        }
    ///    }
    type Error = anyhow::Error;
    fn try_from(config_path: &Path) -> Result<Self, Self::Error> {
        let file = File::open(config_path)
            .map_err(|e| anyhow!("failed to open KBS config file {}", e.to_string()))?;

        serde_json::from_reader::<File, Config>(file)
            .map_err(|e| anyhow!("failed to parse KBS config file {}", e.to_string()))
    }
}
