// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct AttestationConfig {
    #[serde(flatten)]
    pub attestation_service: AttestationServiceConfig,

    pub timeout: i64,
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
