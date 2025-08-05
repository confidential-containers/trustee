use std::process::exit;

fn real_main() -> Result<(), String> {
    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;

    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/reference.proto").map_err(|e| format!("{e}"))?;

    #[cfg(feature = "rvps-rebuild-grpc")]
    protoc_grpcio::compile_grpc_protos(
        &["../protos/reference.proto"],
        &["../protos"],
        &"src/rvps",
        None,
    )
    .map_err(|e| format!("{e}"))?;
    Ok(())
}

fn main() -> shadow_rs::SdResult<()> {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {e}");
        exit(1);
    }

    shadow_rs::new()
}
