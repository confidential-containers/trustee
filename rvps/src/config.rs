// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//
use anyhow::{Context, Result};
use key_value_storage::StorageBackendConfig;
use serde::Deserialize;

use crate::extractors::ExtractorsConfig;

/// Hint added to config parse errors when format may have changed.
/// TODO: update the link to the new version of RVPS, or remove the hint.
const CONFIG_FORMAT_MIGRATION_HINT: &str =
    "\nProbably you are upgrading from an older version, and the RVPS configuration schema may have changed (for example, `storage.type` and `storage.file_path` are no longer used).
    For more information, use the `--print-example-config` subcommand/flag to print an example configuration for your version, then compare/update your config accordingly.

    You can also refer to the RVPS documentation:

https://github.com/confidential-containers/trustee/blob/main/rvps/README.md 
(Tip: for an exact match to this binary, replace `main` with the `commit` hash printed at startup.)";

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub storage: StorageBackendConfig,

    #[serde(default)]
    pub extractors: Option<ExtractorsConfig>,
}

impl Config {
    /// An example RVPS configuration in TOML format with per-field comments.
    pub fn example_config_toml() -> &'static str {
        r#"# RVPS example configuration (TOML)
# This file is meant as a starting point for new deployments and upgrades.

# Storage backend used by RVPS to persist reference values.
[storage]
# Storage type. Common values: "Memory", "LocalFs", "LocalJson", "Postgres".
storage_type = "LocalFs"

[storage.backends.local_fs]
# Directory path where RVPS stores its data.
dir_path = "/opt/confidential-containers/rvps/storage"

# Optional: configure provenance extractors.
# The exact extractor keys depend on which extractors are compiled/enabled.
#
# [extractors]
# swid_extractor = {}
"#
    }

    pub fn from_file(config_path: &str) -> Result<Self> {
        let c = config::Config::builder()
            .add_source(config::File::with_name(config_path))
            .build()?;

        let res = c
            .try_deserialize()
            .context("invalid config")
            .context(CONFIG_FORMAT_MIGRATION_HINT)?;
        Ok(res)
    }
}
