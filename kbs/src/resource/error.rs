// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[cfg(feature = "aliyun")]
    #[error("Aliyun KMS backend error")]
    AliyunError {
        #[source]
        source: anyhow::Error,
    },

    #[error("Illegal Resource Description")]
    IllegalResourceDescription,

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
