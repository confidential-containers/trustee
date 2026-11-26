// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AttestationError {
    #[error("attestation token verification failed: {0}")]
    InvalidToken(#[source] kbs::token::Error),
    #[error("attestation policy denied the request: {0}")]
    PolicyDenied(String),
    #[error("attestation policy evaluation failed: {0}")]
    PolicyEvaluation(#[source] policy_engine::PolicyError),
}

impl AttestationError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::InvalidToken(_) => 401,
            Self::PolicyDenied(_) => 403,
            Self::PolicyEvaluation(_) => 503,
        }
    }
}
