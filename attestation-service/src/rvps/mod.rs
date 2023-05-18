// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

extern crate strum;

#[allow(clippy::new_without_default)]
pub mod extractors;
pub mod pre_processor;
pub mod reference_value;
pub mod store;

#[cfg(feature = "rvps-grpc")]
pub mod grpc;
#[cfg(feature = "rvps-grpc")]
pub use grpc::Agent;

#[cfg(feature = "rvps-native")]
pub mod native;
#[cfg(feature = "rvps-native")]
pub use native::Core;

use anyhow::*;
use serde::{Deserialize, Serialize};

pub use reference_value::{ReferenceValue, TrustedDigest};
pub use store::Store;

/// Default version of Message
static MESSAGE_VERSION: &str = "0.1.0";

/// Message is an overall packet that Reference Value Provider Service
/// receives. It will contain payload (content of different provenance,
/// JSON format), provenance type (indicates the type of the payload)
/// and a version number (use to distinguish different version of
/// message, for extendability).
/// * `version`: version of this message.
/// * `payload`: content of the provenance, JSON encoded.
/// * `type`: provenance type of the payload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Message {
    #[serde(default = "default_version")]
    version: String,
    payload: String,
    r#type: String,
}

/// Set the default version for Message
fn default_version() -> String {
    MESSAGE_VERSION.into()
}

/// The interfaces of Reference Value Provider Service
/// * `verify_and_extract` is responsible for verify a message and
/// store reference values from it.
/// * `get_digests` gets trusted digests by the artifact's name.
#[async_trait::async_trait]
pub trait RVPSAPI {
    async fn verify_and_extract(&mut self, message: Message) -> Result<()>;
    async fn get_digests(&self, name: &str) -> Result<Option<TrustedDigest>>;
}
