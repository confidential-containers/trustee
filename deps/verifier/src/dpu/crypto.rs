// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic utilities for DICE verification.
//!
//! Implements ECDSA P-384 signature verification and SHA-384 hashing
//! as required by the TCG DICE specification and Tri-Secure paper §5.4.

use super::error::{VerifierError, VerifierResult};
use p384::ecdsa::{Signature, VerifyingKey};
use p384::PublicKey;
use sha2::{Digest, Sha384};

/// Computes SHA-384 hash of the input data.
pub fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// Computes HMAC-SHA-384 (RFC 2104) using raw SHA-384 primitives.
///
/// This avoids depending on the `hmac` crate which has digest version
/// constraints. The implementation follows RFC 2104 exactly:
///   HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))
pub fn hmac_sha384(key: &[u8], data: &[u8]) -> VerifierResult<Vec<u8>> {
    const BLOCK_SIZE: usize = 128; // SHA-384 block size
    const IPAD: u8 = 0x36;
    const OPAD: u8 = 0x5c;

    // Step 1: Normalize key to block size
    let k_prime = if key.len() > BLOCK_SIZE {
        let mut padded = sha384(key);
        padded.resize(BLOCK_SIZE, 0);
        padded
    } else {
        let mut padded = key.to_vec();
        padded.resize(BLOCK_SIZE, 0);
        padded
    };

    // Step 2: inner hash = H((K' XOR ipad) || message)
    let mut inner_key = vec![0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        inner_key[i] = k_prime[i] ^ IPAD;
    }
    let mut inner_hasher = Sha384::new();
    inner_hasher.update(&inner_key);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    // Step 3: outer hash = H((K' XOR opad) || inner_hash)
    let mut outer_key = vec![0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        outer_key[i] = k_prime[i] ^ OPAD;
    }
    let mut outer_hasher = Sha384::new();
    outer_hasher.update(&outer_key);
    outer_hasher.update(&inner_hash);
    Ok(outer_hasher.finalize().to_vec())
}

/// Serializes a P-384 public key to SEC1 bytes (uncompressed).
pub fn pubkey_to_bytes(pk: &PublicKey) -> Vec<u8> {
    use p384::elliptic_curve::sec1::ToEncodedPoint;
    let point = pk.to_encoded_point(false);
    point.as_bytes().to_vec()
}

/// Deserializes a P-384 public key from SEC1 bytes.
pub fn pubkey_from_bytes(data: &[u8]) -> VerifierResult<PublicKey> {
    use p384::elliptic_curve::sec1::FromEncodedPoint;
    let point = p384::EncodedPoint::from_bytes(data)
        .map_err(|e| VerifierError::MalformedEvidence(format!("public key SEC1: {}", e)))?;

    PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| VerifierError::MalformedEvidence("invalid public key point".into()))
}

/// Verifies an ECDSA P-384 signature.
///
/// # Arguments
/// * `public_key` - The P-384 public key to verify against
/// * `message` - The message bytes that were signed
/// * `signature` - The DER-encoded ECDSA signature
pub fn verify_ecdsa_p384(
    public_key: &PublicKey,
    message: &[u8],
    signature: &[u8],
) -> VerifierResult<()> {
    let verifying_key = VerifyingKey::from(public_key.clone());

    let sig = Signature::from_der(signature).map_err(|e| {
        VerifierError::SignatureVerification(format!("DER decode: {}", e))
    })?;

    use p384::ecdsa::signature::Verifier;
    verifying_key
        .verify(message, &sig)
        .map_err(|e| VerifierError::SignatureVerification(format!("P-384 verify: {}", e)))
}

#[cfg(test)]
use p384::SecretKey;

/// Generates a test key pair for unit tests.
#[cfg(test)]
pub fn test_keypair() -> (SecretKey, PublicKey) {
    use rand_core::OsRng;
    let secret = SecretKey::random(&mut OsRng);
    let public = secret.public_key();
    (secret, public)
}

/// Returns a test public key for use in test structs.
#[cfg(test)]
pub fn test_public_key() -> PublicKey {
    test_keypair().1
}

/// Signs a message with a secret key (for test fixtures).
#[cfg(test)]
pub fn sign_ecdsa_p384(secret: &SecretKey, message: &[u8]) -> Vec<u8> {
    use p384::ecdsa::{signature::Signer, SigningKey};
    let signing_key = SigningKey::from(secret.clone());
    let sig: Signature = signing_key.sign(message);
    sig.to_der().as_bytes().to_vec()
}

// --- Serde helpers for PublicKey ---

pub mod serde_pubkey {
    use super::{pubkey_from_bytes, pubkey_to_bytes};
    use p384::PublicKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(pk: &PublicKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = pubkey_to_bytes(pk);
        serializer.serialize_bytes(&bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        pubkey_from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}
