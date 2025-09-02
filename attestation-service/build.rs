use std::process::exit;

use shadow_rs::{BuildPattern, ShadowBuilder};

fn real_main() -> Result<(), String> {
    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/attestation.proto").map_err(|e| format!("{e}"))?;

    #[cfg(feature = "grpc-bin")]
    tonic_build::compile_protos("../protos/reference.proto").map_err(|e| format!("{e}"))?;
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
