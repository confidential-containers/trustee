use std::path::{Path, PathBuf};

use anyhow::{bail, Ok, Result};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509};

/// Write `contents` to `path`. Error if `path` already exists.
fn safe_write(path: &Path, contents: Vec<u8>) -> Result<()> {
    if path.try_exists()? {
        bail!("refusing to overwrite file: {:?}", path);
    } else {
        std::fs::write(&path, contents)?;
        Ok(())
    }
}

fn get_key_paths(base_dir: &Path, key_name: &str) -> (PathBuf, PathBuf) {
    let private_path = base_dir.join(key_name);
    let public_path = private_path.with_extension("pub");
    (private_path, public_path)
}

/// Write a key to separate files: one for private, one for public.
fn write_pem(private_path: &Path, public_path: &Path, private_key: &PKey<Private>) -> Result<()> {
    let private_pem = private_key.private_key_to_pem_pkcs8()?;
    safe_write(&private_path, private_pem)?;

    let public_pem = private_key.public_key_to_pem()?;
    safe_write(&public_path, public_pem)?;

    Ok(())
}

/// Generate a new key for authentication and write to the given file paths.
pub(crate) fn write_new_auth_key_pair(private_path: &Path, public_path: &Path) -> Result<()> {
    let private_key = PKey::generate_ed25519()?;
    write_pem(&private_path, &public_path, &private_key)
}

/// Ensure a key pair for authentication exists in the given home directory.
///
/// Create the key files if they don't exist.
/// Return the path to the private and public keys.
pub(crate) fn ensure_auth_key_pair(home_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let (private_path, public_path) = get_key_paths(home_dir, "auth_key");

    if !private_path.try_exists()? {
        write_new_auth_key_pair(&private_path, &public_path)?;
    }

    Ok((private_path, public_path))
}

/// Ensure a key pair for HTTPS exists in the given home directory.
///
/// Create the key files if they don't exist.
/// Return the path to the private and public keys.
pub(crate) fn ensure_https_key_pair(home_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let (private_path, public_path) = get_key_paths(home_dir, "https_key");

    if !private_path.try_exists()? {
        let rsa = Rsa::generate(2048)?;
        let private_key = PKey::from_rsa(rsa)?;

        write_pem(&private_path, &public_path, &private_key)?;
    }

    Ok((private_path, public_path))
}

/// Generate a new certificate for HTTPS and write it to the given path.
///
/// Use the given private key to sign the certificate.
fn write_new_https_cert(certificate_path: &Path, private_path: &Path) -> Result<()> {
    // Load the private key from the provided path
    let private_key = {
        let private_key_data = std::fs::read(private_path)?;
        PKey::private_key_from_pem(&private_key_data)?
    };

    let name = {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("CN", "localhost")?;
        name_builder.build()
    };

    // Create a self-signed certificate
    let certificate = {
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(name.as_ref())?;
        builder.set_issuer_name(name.as_ref())?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(365)?.as_ref())?;
        builder.set_pubkey(private_key.as_ref())?;
        builder.set_serial_number(
            openssl::asn1::Asn1Integer::from_bn(openssl::bn::BigNum::from_u32(1)?.as_ref())?
                .as_ref(),
        )?;
        builder.sign(private_key.as_ref(), MessageDigest::sha256())?;
        builder.build()
    };

    // Write certificate to file
    safe_write(&certificate_path, certificate.to_pem()?)
}

/// Ensure a HTTPS certificate exists in the given home directory.
///
/// Create a self-signed certificate if it doesn't exist.
///
/// Returns the path to the certificate.
pub(crate) fn ensure_https_cert(home_dir: &Path, private_path: &Path) -> Result<PathBuf> {
    let certificate_path = home_dir.join("https_cert.pem");

    if !certificate_path.try_exists()? {
        write_new_https_cert(&certificate_path, private_path)?;
    }

    Ok(certificate_path)
}
