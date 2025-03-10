use std::process::exit;

fn real_main() -> Result<(), String> {
    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;

    tonic_build::compile_protos("../protos/reference.proto").map_err(|e| format!("{e}"))?;
    Ok(())
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {e}");
        exit(1);
    }

    shadow_rs::ShadowBuilder::builder()
    .build_pattern(shadow_rs::BuildPattern::RealTime)
    .build().unwrap();
}
