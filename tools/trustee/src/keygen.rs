use anyhow::Result;
use log::info;
use std::path::Path;

use crate::write_new_auth_key_pair;

pub(crate) fn trustee_keygen(private_path: &Path) -> Result<()> {
    let public_path = private_path.with_extension("pub");
    write_new_auth_key_pair(&private_path, &public_path)?;
    info!("Wrote new private key: {:?}", private_path);
    info!("Wrote new public key: {:?}", public_path);
    Ok(())
}
