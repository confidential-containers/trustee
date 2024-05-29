// Copyright (c) 2024 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use strum::{AsRefStr, EnumString};

/// Hash algorithms used to calculate eventlog
#[derive(EnumString, AsRefStr, Clone)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha256")]
    Sha256,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha384")]
    Sha384,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha512")]
    Sha512,
}
