// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Failed to verify Attestation Token")]
    TokenVerificationFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to initialize Token Verifier")]
    TokenVerifierInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Tee public key is not found inside the claims of token")]
    NoTeePubKeyClaimFound,

    #[error("Failed to parse Tee public key")]
    TeePubKeyParseFailed,
}
