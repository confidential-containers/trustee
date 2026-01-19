// Copyright (c) 2025 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

pub type Result<T> = std::result::Result<T, KeyValueStorageError>;

#[derive(Error, Debug)]
pub enum KeyValueStorageError {
    #[error("failed to set key `{key}`: {source}")]
    SetKeyFailed {
        #[source]
        source: anyhow::Error,
        key: String,
    },

    #[error("failed to get key `{key}`: {source}")]
    GetKeyFailed {
        #[source]
        source: anyhow::Error,
        key: String,
    },

    #[error("failed to list keys: {source}")]
    ListKeysFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("failed to delete key `{key}`: {source}")]
    DeleteKeyFailed {
        #[source]
        source: anyhow::Error,
        key: String,
    },

    #[error("failed to initialize backend: {source}")]
    InitializeBackendFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("malformed value: {source}")]
    MalformedValue {
        #[source]
        source: anyhow::Error,
    },

    #[error("invalid configuration: {message}")]
    InvalidConfiguration { message: String },
}
