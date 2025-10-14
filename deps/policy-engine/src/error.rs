// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

pub type Result<T> = std::result::Result<T, PolicyError>;

#[derive(Error, Debug)]
pub enum PolicyError {
    // Global Errors
    #[error("Serde json error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("Base64 decode attestation service policy string failed: {0}")]
    Base64DecodeFailed(#[from] base64::DecodeError),

    #[error("Illegal policy id. Only support alphabet, numeric, `-` or `_`")]
    InvalidPolicyId,

    #[error("Malformed policy: {0}")]
    MalformedPolicy(#[source] anyhow::Error),

    // Backend Related Errors
    #[error("backend error: {0}")]
    BackendError(#[from] key_value_storage::KeyValueStorageError),

    // Opa Related Errors
    #[error("Failed to load policy: {0}")]
    LoadPolicyFailed(#[source] anyhow::Error),

    #[error("Failed to load reference data: {0}")]
    LoadReferenceDataFailed(#[source] anyhow::Error),

    #[error("Failed to set input data: {0}")]
    SetInputDataFailed(#[source] anyhow::Error),

    #[error("json serialization failed: {0}")]
    JsonSerializationFailed(#[source] anyhow::Error),

    #[error("Failed to eval policy: {0}")]
    EvalPolicyFailed(#[source] anyhow::Error),
}
