// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::config::Config;
use anyhow::*;
use as_types::AttestationResults;
use async_trait::async_trait;
use kbs_types::Tee;
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(feature = "grpc-as")]
mod grpc;

#[cfg(any(feature = "native-as", feature = "native-as-no-verifier"))]
mod native;

/// Interface of Attestation Service
#[async_trait]
pub trait Attest: Send + Sync {
    /// Verify Attestation Evidence
    async fn attest_verify(
        &mut self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults>;
}

/// Attestation Service handler
#[derive(Clone)]
pub struct AttestVerifier {
    /// Attestation Service instance
    pub attest_verifier: Arc<Mutex<dyn Attest>>,
}

impl AttestVerifier {
    /// Create and initilize AttestVerifier
    pub async fn new(kbs_config: &Config) -> Result<Self> {
        let attest_verifier: Arc<Mutex<dyn Attest>> = {
            cfg_if::cfg_if! {
                if #[cfg(any(feature = "native-as", feature = "native-as-no-verifier"))] {
                    Arc::new(Mutex::new(native::Native::new(&kbs_config.as_config_file_path)?))
                } else if #[cfg(feature = "grpc-as")] {
                    Arc::new(Mutex::new(grpc::Grpc::new(kbs_config).await?))
                } else {
                    compile_error!("Please enable at least one of the following features: `native-as`, `native-as-no-verifier`, or `grpc-as` to continue.");
                }
            }
        };

        Ok(Self { attest_verifier })
    }
}
