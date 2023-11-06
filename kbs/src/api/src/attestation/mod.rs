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
    async fn set_policy(&mut self, _input: &[u8]) -> Result<()> {
        Err(anyhow!("Set Policy API is unimplemented"))
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
