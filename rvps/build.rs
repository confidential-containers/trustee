use std::process::exit;

use shadow_rs::{BuildPattern, ShadowBuilder};

fn real_main() -> Result<(), String> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed={out_dir}");
    println!("cargo:rustc-link-search=native={out_dir}");

    #[cfg(feature = "rebuild-grpc-protos")]
    tonic_prost_build::configure()
        .protoc_arg("--experimental_allow_proto3_optional")
        .out_dir("src/rvps_api")
        .compile_protos(&["../protos/reference.proto"], &["../protos"])
        .map_err(|e| format!("Failed to build gRPC protos: {e}"))?;

    Ok(())
}

fn main() -> shadow_rs::SdResult<()> {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {e}");
        exit(1);
    }

    let _ = ShadowBuilder::builder()
        .build_pattern(BuildPattern::RealTime)
        .build()?;
    Ok(())
}
