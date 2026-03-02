// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use strum::AsRefStr;
use thiserror::Error;
use tracing::error;

pub type Result<T> = std::result::Result<T, KbsPolicyEngineError>;

#[derive(Error, AsRefStr, Debug)]
pub enum KbsPolicyEngineError {
    #[error("Failed to evaluate policy {0}")]
    EvaluationError(#[from] anyhow::Error),

    #[error("Failed to load data for policy")]
    DataLoadError,

    #[error("Invalid resource path format")]
    ResourcePathError,

    #[error("Policy IO Error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("Decoding (base64) policy failed: {0}")]
    DecodeError(#[from] base64::DecodeError),

    #[error("Failed to load input for policy")]
    InputError,

    #[error("Failed to load policy")]
    PolicyLoadError,

    #[error("Set Policy request is illegal for {0}")]
    IllegalSetPolicyRequest(&'static str),

    #[error("Failed to set policy, illegal policy: {0}")]
    InvalidPolicy(#[source] anyhow::Error),
}
