use std::process::exit;

fn real_main() -> Result<(), String> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed={out_dir}");
    println!("cargo:rustc-link-search=native={out_dir}");

    tonic_build::compile_protos("../../bin/rvps/proto/reference.proto")
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
