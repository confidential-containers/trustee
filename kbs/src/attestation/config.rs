// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

pub const DEFAULT_TIMEOUT: i64 = 5;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AttestationConfig {
    #[serde(flatten)]
    #[serde(default)]
    pub attestation_service: AttestationServiceConfig,

    #[serde(default = "default_timeout")]
    pub timeout: i64,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            attestation_service: AttestationServiceConfig::default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

fn default_timeout() -> i64 {
    DEFAULT_TIMEOUT
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum AttestationServiceConfig {
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    #[serde(alias = "coco_as_builtin")]
    CoCoASBuiltIn(attestation_service::config::Config),

    #[cfg(feature = "coco-as-grpc")]
    #[serde(alias = "coco_as_grpc")]
    CoCoASGrpc(super::coco::grpc::GrpcConfig),

    #[cfg(feature = "intel-trust-authority-as")]
    #[serde(alias = "intel_ta")]
    IntelTA(super::intel_trust_authority::IntelTrustAuthorityConfig),
}

impl Default for AttestationServiceConfig {
    fn default() -> Self {
        cfg_if::cfg_if! {
            if #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))] {
                AttestationServiceConfig::CoCoASBuiltIn(attestation_service::config::Config::default())
            } else if #[cfg(feature = "coco-as-grpc")] {
                AttestationServiceConfig::CoCoASGrpc(super::coco::grpc::GrpcConfig::default())
            } else {
                AttestationServiceConfig::IntelTA(super::intel_trust_authority::IntelTrustAuthorityConfig::default())
            }
        }
    }
}
