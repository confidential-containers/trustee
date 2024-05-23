// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(missing_docs)]
#[allow(unused_imports)]
use std::process::Command;

fn main() -> Result<(), String> {
    #[cfg(feature = "tonic-build")]
    tonic_build::compile_protos("../../../attestation-service/protos/attestation.proto")
        .map_err(|e| format!("{e}"))?;

    Ok(())
}
