// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use async_trait::async_trait;
#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
use attestation_service::config::Config as AsConfig;
use base64::{engine::general_purpose::STANDARD, Engine};
#[cfg(feature = "coco-as-grpc")]
use coco::grpc::*;
#[cfg(feature = "intel-trust-authority-as")]
use intel_trust_authority::*;
use kbs_types::{Challenge, Tee};
use rand::{thread_rng, Rng};

#[cfg(not(feature = "intel-trust-authority-as"))]
pub const AS_TOKEN_TEE_PUBKEY_PATH: &str = "/customized_claims/runtime_data/tee-pubkey";
#[cfg(feature = "intel-trust-authority-as")]
pub const AS_TOKEN_TEE_PUBKEY_PATH: &str = "/attester_runtime_data/tee-pubkey";

#[cfg(feature = "coco-as")]
#[allow(missing_docs)]
pub mod coco;

#[cfg(feature = "intel-trust-authority-as")]
pub mod intel_trust_authority;

/// Interface for Attestation Services.
///
/// Attestation Service implementations should implement this interface.
#[async_trait]
pub trait Attest: Send + Sync {
    /// Set Attestation Policy
    async fn set_policy(&self, _policy_id: &str, _policy: &str) -> Result<()> {
        Err(anyhow!("Set Policy API is unimplemented"))
    }

    /// Verify Attestation Evidence
    /// Return Attestation Results Token
    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String>;

    /// generate the Challenge to pass to attester based on Tee and nonce
    async fn generate_challenge(&self, _tee: Tee, _tee_parameters: String) -> Result<Challenge> {
        let mut nonce: Vec<u8> = vec![0; 32];

        thread_rng()
            .try_fill(&mut nonce[..])
            .map_err(anyhow::Error::from)?;

        let nonce = STANDARD.encode(&nonce);
        Ok(Challenge {
            nonce,
            extra_params: String::new(),
        })
    }
}

/// Attestation Service
pub enum AttestationService {
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    CoCoASBuiltIn(coco::builtin::BuiltInCoCoAs),

    #[cfg(feature = "coco-as-grpc")]
    CoCoASgRPC(GrpcClientPool),

    #[cfg(feature = "intel-trust-authority-as")]
    IntelTA(IntelTrustAuthority),
}

impl AttestationService {
    /// Create and initialize AttestationService.
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    pub async fn new(config: AsConfig) -> Result<Self> {
        let built_in_as = coco::builtin::BuiltInCoCoAs::new(config).await?;
        Ok(Self::CoCoASBuiltIn(built_in_as))
    }

    /// Create and initialize AttestationService.
    #[cfg(feature = "coco-as-grpc")]
    pub async fn new(config: GrpcConfig) -> Result<Self> {
        let pool = GrpcClientPool::new(config).await?;
        Ok(Self::CoCoASgRPC(pool))
    }

    /// Create and initialize AttestationService.
    #[cfg(feature = "intel-trust-authority-as")]
    pub fn new(config: IntelTrustAuthorityConfig) -> Result<Self> {
        let ta_client = intel_trust_authority::IntelTrustAuthority::new(config)?;
        Ok(Self::IntelTA(ta_client))
    }

    pub async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> Result<String> {
        match self {
            #[cfg(feature = "coco-as-grpc")]
            AttestationService::CoCoASgRPC(inner) => inner.verify(tee, nonce, attestation).await,
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationService::CoCoASBuiltIn(inner) => inner.verify(tee, nonce, attestation).await,
            #[cfg(feature = "intel-trust-authority-as")]
            AttestationService::IntelTA(inner) => inner.verify(tee, nonce, attestation).await,
        }
    }

    pub async fn set_policy(&self, policy_id: &str, policy: &str) -> Result<()> {
        match self {
            #[cfg(feature = "coco-as-grpc")]
            AttestationService::CoCoASgRPC(inner) => inner.set_policy(policy_id, policy).await,
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationService::CoCoASBuiltIn(inner) => inner.set_policy(policy_id, policy).await,
            #[cfg(feature = "intel-trust-authority-as")]
            AttestationService::IntelTA(inner) => inner.set_policy(policy_id, policy).await,
        }
    }

    pub async fn generate_challenge(&self, tee: Tee, tee_parameters: String) -> Result<Challenge> {
        match self {
            #[cfg(feature = "coco-as-grpc")]
            AttestationService::CoCoASgRPC(inner) => {
                inner.generate_challenge(tee, tee_parameters).await
            }
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationService::CoCoASBuiltIn(inner) => {
                inner.generate_challenge(tee, tee_parameters).await
            }
            #[cfg(feature = "intel-trust-authority-as")]
            AttestationService::IntelTA(inner) => {
                inner.generate_challenge(tee, tee_parameters).await
            }
        }
    }
}
