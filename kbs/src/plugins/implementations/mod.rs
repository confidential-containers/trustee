// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "nebula-ca-plugin")]
pub mod nebula_ca;
#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "pki-vault-plugin")]
pub mod pki_vault;
pub mod resource;
pub mod sample;

#[cfg(feature = "nebula-ca-plugin")]
pub use nebula_ca::{NebulaCaPlugin, NebulaCaPluginConfig};
#[cfg(feature = "pkcs11")]
pub use pkcs11::{Pkcs11Backend, Pkcs11Config};
#[cfg(feature = "pki-vault-plugin")]
pub use pki_vault::{PKIVaultPlugin, PKIVaultPluginConfig};
pub use resource::{RepositoryConfig, ResourceStorage};
pub use sample::{Sample, SampleConfig};
