use std::path::{Path, PathBuf};

use anyhow::{bail, Ok, Result};
use openssl::pkey::{PKey, Private};

fn safe_write(path: &Path, contents: Vec<u8>) -> Result<()> {
    if path.exists() {
        bail!("refusing to overwrite file: {:?}", path);
    } else {
        std::fs::write(&path, contents)?;
        Ok(())
    }
}

/// Writes the private and public keys to separate PEM files.
/// `path` is the base path where the keys will be saved.
/// Returns the paths to the private and public key.
fn write_pem(base_path: &Path, private_key: &PKey<Private>) -> Result<(PathBuf, PathBuf)> {
    let private_path = base_path.with_extension("pem");
    let private_pem = private_key.private_key_to_pem_pkcs8()?;
    safe_write(&private_path, private_pem)?;

    let public_path = base_path.with_extension("pub");
    let public_pem = private_key.public_key_to_pem()?;
    safe_write(&public_path, public_pem)?;

    Ok((private_path, public_path))
}

/// Creates a key pair and writes to separate files.
pub fn new_auth_key_pair(base_path: &Path) -> Result<(PathBuf, PathBuf)> {
    let private_key = PKey::generate_ed25519()?;
    write_pem(base_path, &private_key)
}
