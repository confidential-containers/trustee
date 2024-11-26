// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use log::error;
use strum::AsRefStr;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, AsRefStr, Debug)]
pub enum Error {
    #[error("Failed to initialize attestation service")]
    AttestationServiceInitialization {
        #[source]
        source: anyhow::Error,
    },

    #[error("Failed to extract Tee public key from claims")]
    ExtractTeePubKeyFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("RCAR handshake Auth failed: {source}")]
    RcarAuthFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("RCAR handshake Attest failed")]
    RcarAttestFailed {
        #[source]
        source: anyhow::Error,
    },

    #[error("Set Attestation Policy failed")]
    SetPolicy {
        #[source]
        source: anyhow::Error,
    },
}
