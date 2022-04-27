use std::process::{exit, Command};

fn real_main() -> Result<(), String> {
    let out_dir = std::env::var("OUT_DIR").unwrap();
    println!("cargo:rerun-if-changed={}", out_dir);
    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=opa");
    let opa_dir = "./src/core/verifier/policy/opa".to_string();
    let opa = Command::new("go")
        .args(&[
            "build",
            "-o",
            &format!("{}/libopa.a", out_dir),
            "-buildmode=c-archive",
            "opa.go",
        ])
        .current_dir(opa_dir)
        .output()
        .expect("failed to launch opa compile process");
    if !opa.status.success() {
        return Err(std::str::from_utf8(&opa.stderr.to_vec())
            .unwrap()
            .to_string());
    }

    Ok(())
}

fn main() {
    if let Err(e) = real_main() {
        eprintln!("ERROR: {}", e);
        exit(1);
    }
}
