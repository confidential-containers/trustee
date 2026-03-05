// Copyright (c) 2026 by Trustee Contributors
//
// SPDX-License-Identifier: Apache-2.0

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    tonic_prost_build::configure()
        .file_descriptor_set_path(out_dir.join("plugin_descriptor.bin"))
        .compile_protos(&["../protos/plugin.proto"], &["../protos"])?;
    Ok(())
}
