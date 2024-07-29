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

/// Number of bytes in a nonce.
const NONCE_SIZE_BYTES: usize = 32;

/// Create a nonce and return as a base-64 encoded string.
pub async fn make_nonce() -> Result<String> {
    let mut nonce: Vec<u8> = vec![0; NONCE_SIZE_BYTES];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(STANDARD.encode(&nonce))
}

pub(crate) async fn generic_generate_challenge(
    _tee: Tee,
    _tee_parameters: serde_json::Value,
) -> Result<Challenge> {
    let nonce = make_nonce().await?;

    Ok(Challenge {
        nonce,
        extra_params: serde_json::Value::String(String::new()),
    })
}

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
    async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: serde_json::Value,
    ) -> Result<Challenge> {
        generic_generate_challenge(tee, tee_parameters).await
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
    pub async fn new(config: IntelTrustAuthorityConfig) -> Result<Self> {
        let ta_client = intel_trust_authority::IntelTrustAuthority::new(config).await?;
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

    pub async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: serde_json::Value,
    ) -> Result<Challenge> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_make_nonce() {
        const BITS_PER_BYTE: usize = 8;

        /// A base-64 encoded value is this many bits in length.
        const BASE64_BITS_CHUNK: usize = 6;

        /// Number of bytes that base64 encoding requires the result to align on.
        const BASE64_ROUNDING_MULTIPLE: usize = 4;

        /// The nominal base64 encoded length.
        const BASE64_NONCE_LENGTH_UNROUNDED_BYTES: usize =
            (NONCE_SIZE_BYTES * BITS_PER_BYTE) / BASE64_BITS_CHUNK;

        /// The actual base64 encoded length is rounded up to the specified multiple.
        const EXPECTED_LENGTH_BYTES: usize =
            BASE64_NONCE_LENGTH_UNROUNDED_BYTES.next_multiple_of(BASE64_ROUNDING_MULTIPLE);

        // Number of nonce tests to run (arbitrary)
        let nonce_count = 13;

        let mut nonces = vec![];

        for _ in 0..nonce_count {
            let nonce = make_nonce().await.unwrap();

            assert_eq!(nonce.len(), EXPECTED_LENGTH_BYTES);

            let found = nonces.contains(&nonce);

            // The nonces should be unique
            assert_eq!(found, false);

            nonces.push(nonce);
        }
    }
}
