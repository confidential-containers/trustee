// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#![allow(missing_docs)]
#[allow(unused_imports)]
use std::process::Command;

fn main() -> Result<(), String> {
    #[cfg(feature = "opa")]
    {
        let out_dir = std::env::var("OUT_DIR").unwrap();
        println!("cargo:rerun-if-changed={out_dir}");
        println!("cargo:rustc-link-search=native={out_dir}");
        println!("cargo:rustc-link-lib=static=cgo");
        let cgo_dir = "./src/policy_engine/opa/cgo".to_string();
        let cgo = Command::new("go")
            .args([
                "build",
                "-o",
                &format!("{out_dir}/libcgo.a"),
                "-buildmode=c-archive",
                "opa.go",
            ])
            .current_dir(cgo_dir)
            .output()
            .expect("failed to launch opa compile process");
        if !cgo.status.success() {
            return Err(std::str::from_utf8(&cgo.stderr.to_vec())
                .unwrap()
                .to_string());
        }
    }

    #[cfg(feature = "tonic-build")]
    tonic_build::compile_protos("../../../attestation-service/protos/attestation.proto")
        .map_err(|e| format!("{e}"))?;

    Ok(())
}
