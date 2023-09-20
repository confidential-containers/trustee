// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "amber-as")]
use amber::AmberConfig;
use anyhow::*;
use async_trait::async_trait;
#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
use attestation_service::config::Config as AsConfig;
#[cfg(feature = "coco-as-grpc")]
use coco::grpc::GrpcConfig;
use kbs_types::Tee;
use std::sync::Arc;
use tokio::sync::Mutex;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand::{thread_rng, Rng};

#[cfg(feature = "coco-as")]
#[allow(missing_docs)]
pub mod coco;

#[cfg(feature = "amber-as")]
pub mod amber;

/// Interface for Attestation Services.
///
/// Attestation Service implementations should implement this interface.
#[async_trait]
pub trait Attest: Send + Sync {
    /// Set Attestation Policy
    async fn set_policy(&mut self, _input: as_types::SetPolicyInput) -> Result<()> {
        Err(anyhow!("Set Policy API is unimplemented"))
    }

    /// Get nonce from AS
    async fn nonce(&mut self) -> Result<String> {
        let mut nonce: Vec<u8> = vec![0; 32];

        thread_rng()
            .try_fill(&mut nonce[..])
            .map_err(anyhow::Error::from)?;

        Ok(STANDARD.encode(&nonce))
    }

    /// Verify Attestation Evidence
    /// Return Attestation Results Token
    async fn verify(&mut self, tee: Tee, nonce: &str, attestation: &str) -> Result<String>;
}

/// Attestation Service
#[derive(Clone)]
pub struct AttestationService(pub Arc<Mutex<dyn Attest>>);

impl AttestationService {
    /// Create and initialize AttestationService.
    #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
    pub fn new(config: &AsConfig) -> Result<Self> {
        let attestation_service: Arc<Mutex<dyn Attest>> =
            Arc::new(Mutex::new(coco::builtin::Native::new(config)?));

        Ok(Self(attestation_service))
    }

    /// Create and initialize AttestationService.
    #[cfg(feature = "coco-as-grpc")]
    pub async fn new(config: &GrpcConfig) -> Result<Self> {
        let attestation_service: Arc<Mutex<dyn Attest>> =
            Arc::new(Mutex::new(coco::grpc::Grpc::new(config).await?));

        Ok(Self(attestation_service))
    }

    /// Create and initialize AttestationService.
    #[cfg(feature = "amber-as")]
    pub fn new(config: &AmberConfig) -> Result<Self> {
        let attestation_service: Arc<Mutex<dyn Attest>> =
            Arc::new(Mutex::new(amber::Amber::new(config)?));

        Ok(Self(attestation_service))
    }
}
