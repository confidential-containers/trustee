// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(missing_docs)]
#[allow(unused_imports)]
use std::process::Command;

fn main() -> Result<(), String> {
    let git_hash = Command::new("git")
        .args(["rev-parse", "--short=10", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=KBS_GIT_HASH={}", git_hash);

    let build_date =
        chrono::Local::now().to_rfc3339_opts(chrono::format::SecondsFormat::Millis, false);
    println!("cargo:rustc-env=KBS_BUILD_DATE={}", build_date);

    #[cfg(feature = "coco-as-grpc")]
    tonic_prost_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;
    #[cfg(feature = "coco-as-grpc")]
    tonic_prost_build::compile_protos("../protos/reference.proto").map_err(|e| format!("{e}"))?;
    #[cfg(feature = "external-plugin")]
    tonic_prost_build::compile_protos("../protos/plugin.proto").map_err(|e| format!("{e}"))?;
    Ok(())
}
