// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod implementations;
pub mod plugin_manager;

pub use implementations::sample;
pub use implementations::resource::{RepositoryConfig, ResourceStorage};

pub use plugin_manager::{PluginManager, PluginsConfig};

pub use implementations::sample::{Sample, SampleConfig};
#[cfg(feature = "nebula-ca-plugin")]
pub use implementations::nebula_ca::{NebulaCaPlugin, NebulaCaPluginConfig};
pub use implementations::spiffe_resource::{SpiffeResourcePlugin, SpiffeResourceConfig};
#[cfg(feature = "pkcs11")]
pub use implementations::pkcs11::{Pkcs11Backend, Pkcs11Config};