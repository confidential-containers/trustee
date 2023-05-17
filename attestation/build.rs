// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(missing_docs)]

use anyhow::*;

fn main() -> Result<()> {
    #[cfg(feature = "tonic-build")]
    tonic_build::compile_protos("../proto/attestation.proto").context("tonic build")?;

    Ok(())
}
