// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type ResourceResult<T> = std::result::Result<T, ResourceError>;

#[derive(Error, AsRefStr, Debug)]
pub enum ResourceError {
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS backend error")]
    AliyunError {
        #[source]
        source: anyhow::Error,
    },

    #[error("Accessed path {path} is illegal")]
    IllegalAccessedPath { path: String },

    #[error("Illegal Resource Description")]
    IllegalResourceDescription,

    #[error("Illegal HTTP method. Only supports `GET` and `POST`")]
    IllegalHttpMethod,

    #[error("Local FS backend error")]
    LocalFs {
        #[source]
        source: anyhow::Error,
    },

    #[error("Malwared Resource Description")]
    MalwaredResourceDescription,

    #[error("Failed to parse Resource Description")]
    ParseResourceDescription,

    #[error("Failed to initialize Resource Storage")]
    ResourceStorageInitialization {
        #[source]
        source: anyhow::Error,
    },
}
