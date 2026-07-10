// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Error types for the DPU verifier.

use thiserror::Error;

/// Verifier error type.
#[derive(Debug, Error)]
pub enum VerifierError {
    #[error("ECDSA signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("DICE chain validation failed at layer {layer}: {reason}")]
    ChainValidation { layer: String, reason: String },

    #[error("FWID mismatch: expected {expected}, got {actual}")]
    FwidMismatch { expected: String, actual: String },

    #[error("RVPS lookup failed for device class '{0}'")]
    RvpsLookupFailed(String),

    #[error("Nonce binding failed: {0}")]
    NonceBindingFailed(String),

    #[error("Certificate expired or not yet valid")]
    CertificateValidity,

    #[error("Malformed DICE evidence: {0}")]
    MalformedEvidence(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Cross-chip binding failed: {0}")]
    BindingFailed(String),

    #[error("OOB channel error: {0}")]
    OobChannel(String),

    #[error("Split-key assembly failed: {0}")]
    SplitKey(String),
}

impl From<p384::elliptic_curve::Error> for VerifierError {
    fn from(e: p384::elliptic_curve::Error) -> Self {
        VerifierError::Crypto(format!("elliptic curve: {}", e))
    }
}


impl From<serde_json::Error> for VerifierError {
    fn from(e: serde_json::Error) -> Self {
        VerifierError::Serialization(e.to_string())
    }
}

impl From<hex::FromHexError> for VerifierError {
    fn from(e: hex::FromHexError) -> Self {
        VerifierError::MalformedEvidence(format!("hex decode: {}", e))
    }
}

/// Result type alias.
pub type VerifierResult<T> = Result<T, VerifierError>;
