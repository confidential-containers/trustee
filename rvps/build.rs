use std::process::exit;

use shadow_rs::{BuildPattern, ShadowBuilder};

fn real_main() -> Result<(), String> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed={out_dir}");
    println!("cargo:rustc-link-search=native={out_dir}");

    #[cfg(feature = "in-toto")]
    {
        println!("cargo:rustc-link-lib=static=cgo");

        let cgo_dir = "./cgo".to_string();
        let cgo = std::process::Command::new("go")
            .args([
                "build",
                "-o",
                &format!("{out_dir}/libcgo.a"),
                "-buildmode=c-archive",
                "intoto.go",
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

    #[cfg(feature = "rebuild-grpc-protos")]
    tonic_build::configure()
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
