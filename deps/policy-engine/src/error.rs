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

    // Policy Storage Related Errors
    #[error("policy storage error: {0}")]
    PolicyStorageError(#[from] key_value_storage::KeyValueStorageError),

    #[error("Policy `{id}` not found")]
    PolicyNotFound { id: String },

    #[error("Policy `{id}` is not a utf-8 string")]
    PolicyIsNotUtf8String {
        id: String,
        #[source]
        source: std::string::FromUtf8Error,
    },

    // Regorus Related Errors
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

    #[error("Failed to add regorus extension: {name} with id {id}: {source}")]
    AddRegorusExtensionFailed {
        name: String,
        id: u8,
        #[source]
        source: anyhow::Error,
    },
}
