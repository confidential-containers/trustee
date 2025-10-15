// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use core::{clone::Clone, convert::TryInto};

use aes_gcm::{
    aead::{generic_array::GenericArray, AeadMutInPlace},
    Aes256Gcm, KeyInit, Nonce,
};
use aes_kw::{Kek, KekAes256};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{ProtectedHeader, Response, TeePubKey};
use log::warn;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use rand::{rngs::OsRng, Rng};
use rsa::{sha2::Sha256, BigUint, Oaep, Pkcs1v15Encrypt, RsaPublicKey};
use serde_json::{json, Map};

/// RSA PKCS#1 v1.5
const RSA1_5_ALGORITHM: &str = "RSA1_5";

/// RSAES OAEP using SHA-256 and MGF1 with SHA-256
const RSA_OAEP256_ALGORITHM: &str = "RSA-OAEP-256";

/// ECDH-ES using Concat KDF and CEK wrapped with "A256KW"
const ECDH_ES_A256KW: &str = "ECDH-ES+A256KW";

/// The elliptic curve key type
const EC_KTY: &str = "EC";

/// The elliptic curve name of p256.
const P256_CURVE: &str = "P-256";

/// The elliptic curve name of p521.
const P521_CURVE: &str = "P-521";

/// AES 256 GCM
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

/// AES 256 GCM Key length in bits
const AES_GCM_256_KEY_BITS: u32 = 256;

/// Use RSAv1.5 to encrypt the payload data.
/// Warning: This algorithm is deprecated per
/// <https://www.ietf.org/archive/id/draft-madden-jose-deprecate-none-rsa15-00.html#section-1.2>
#[deprecated(note = "This algorithm is no longer recommended.")]
fn rsa_1v15(k_mod: String, k_exp: String, mut payload_data: Vec<u8>) -> Result<Response> {
    warn!("Get JWE request using deprecated kcs#1 v1.5 encryption, which has potential security issues.");
    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let protected = ProtectedHeader {
        alg: RSA1_5_ALGORITHM.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: Map::new(),
    };

    let aad = protected.generate_aad().context("Generate JWE AAD")?;

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(k_mod)
        .context("base64 decode k_mod failed")?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(k_exp)
        .context("base64 decode k_exp failed")?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key =
        RsaPublicKey::new(n, e).context("Building RSA key from modulus and exponent failed")?;
    let encrypted_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, aes_sym_key.as_slice())
        .context("RSA encrypt sym key failed")?;

    Ok(Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}

/// Use RSA-OAEP SHA-256 to encrypt the payload data.
fn rsa_oaep256(k_mod: String, k_exp: String, mut payload_data: Vec<u8>) -> Result<Response> {
    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let protected = ProtectedHeader {
        alg: RSA_OAEP256_ALGORITHM.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: Map::new(),
    };

    let aad = protected.generate_aad().context("Generate JWE AAD")?;

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(k_mod)
        .context("base64 decode k_mod failed")?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(k_exp)
        .context("base64 decode k_exp failed")?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key =
        RsaPublicKey::new(n, e).context("Building RSA key from modulus and exponent failed")?;
    let padding = Oaep::new::<Sha256>();
    let encrypted_key = rsa_pub_key
        .encrypt(&mut rng, padding, aes_sym_key.as_slice())
        .context("RSA encrypt sym key failed")?;

    Ok(Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}

/// Use ECDH-ES-A256KW to encrypt the payload data. The EC curve is P256.
fn ecdh_es_a256kw_p256(x: String, y: String, mut payload_data: Vec<u8>) -> Result<Response> {
    let mut rng = rand::thread_rng();

    // 1. Generate a random CEK
    let cek = Aes256Gcm::generate_key(&mut rng);

    // 2. Wrap the CEK and generate ProtectedHeader
    let x: [u8; 32] = URL_SAFE_NO_PAD
        .decode(x)
        .context("base64 decode x failed")?
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of coordinates X"))?;
    let y: [u8; 32] = URL_SAFE_NO_PAD
        .decode(y)
        .context("base64 decode y failed")?
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of coordinates Y"))?;
    let client_point = p256::EncodedPoint::from_affine_coordinates(
        &GenericArray::from(x),
        &GenericArray::from(y),
        false,
    );
    let public_key = p256::PublicKey::from_encoded_point(&client_point)
        .into_option()
        .ok_or(anyhow!("invalid TEE public key"))?;
    let encrypter_secret = p256::ecdh::EphemeralSecret::random(&mut rng);
    let z = encrypter_secret
        .diffie_hellman(&public_key)
        .raw_secret_bytes()
        .to_vec();
    let mut key_derivation_materials = Vec::new();
    key_derivation_materials.extend_from_slice(&(ECDH_ES_A256KW.len() as u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(ECDH_ES_A256KW.as_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&AES_GCM_256_KEY_BITS.to_be_bytes());
    let mut wrapping_key = vec![0; 32];
    concat_kdf::derive_key_into::<rsa::sha2::Sha256>(
        &z,
        &key_derivation_materials,
        &mut wrapping_key,
    )
    .map_err(|e| anyhow!("failed to do concat KDF: {e:?}"))?;
    let wrapping_key: [u8; 32] = wrapping_key
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of AES wrapping key"))?;
    let wrapping_key: KekAes256 = Kek::new(&GenericArray::from(wrapping_key));
    let mut encrypted_key = vec![0; 40];
    encrypted_key.resize(40, 0);
    let cek = cek.to_vec();
    wrapping_key
        .wrap(&cek, &mut encrypted_key)
        .map_err(|e| anyhow!("failed to do AES wrapping: {e:?}"))?;

    let point = p256::EncodedPoint::from(encrypter_secret.public_key());
    let epk_x = point
        .x()
        .ok_or(anyhow!("invalid public key: without coordinate X"))?;
    let epk_y = point
        .y()
        .ok_or(anyhow!("invalid public key: without coordinate Y"))?;
    let epk_x = URL_SAFE_NO_PAD.encode(epk_x);
    let epk_y = URL_SAFE_NO_PAD.encode(epk_y);
    let protected = ProtectedHeader {
        alg: ECDH_ES_A256KW.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: json!({
            "epk": {
                "crv": P256_CURVE,
                "kty": EC_KTY,
                "x": epk_x,
                "y": epk_y
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    };

    // 3. Encrypt content with CEK
    let mut cek_cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));

    let iv = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let aad = protected.generate_aad().context("Generate JWE AAD")?;

    let tag = cek_cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    Ok(Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}

/// Use ECDH-ES-A256KW to encrypt the payload data. The EC curve is P521.
fn ecdh_es_a256kw_p521(x: String, y: String, mut payload_data: Vec<u8>) -> Result<Response> {
    let mut rng = rand::thread_rng();

    // 1. Generate a random CEK
    let cek = Aes256Gcm::generate_key(&mut rng);

    // 2. Wrap the CEK and generate ProtectedHeader
    let x: [u8; 66] = URL_SAFE_NO_PAD
        .decode(x)
        .context("base64 decode x failed")?
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of coordinates X"))?;
    let y: [u8; 66] = URL_SAFE_NO_PAD
        .decode(y)
        .context("base64 decode y failed")?
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of coordinates Y"))?;
    let client_point = p521::EncodedPoint::from_affine_coordinates(
        GenericArray::from_slice(&x),
        GenericArray::from_slice(&y),
        false,
    );
    let public_key = p521::PublicKey::from_encoded_point(&client_point)
        .into_option()
        .ok_or(anyhow!("invalid TEE public key"))?;
    let encrypter_secret = p521::ecdh::EphemeralSecret::random(&mut rng);
    let z = encrypter_secret
        .diffie_hellman(&public_key)
        .raw_secret_bytes()
        .to_vec();
    let mut key_derivation_materials = Vec::new();
    key_derivation_materials.extend_from_slice(&(ECDH_ES_A256KW.len() as u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(ECDH_ES_A256KW.as_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&(0_u32).to_be_bytes());
    key_derivation_materials.extend_from_slice(&AES_GCM_256_KEY_BITS.to_be_bytes());
    let mut wrapping_key = vec![0; 32];
    concat_kdf::derive_key_into::<rsa::sha2::Sha256>(
        &z,
        &key_derivation_materials,
        &mut wrapping_key,
    )
    .map_err(|e| anyhow!("failed to do concat KDF: {e:?}"))?;
    let wrapping_key: [u8; 32] = wrapping_key
        .try_into()
        .map_err(|_| anyhow!("invalid bytes length of AES wrapping key"))?;
    let wrapping_key: KekAes256 = Kek::new(&GenericArray::from(wrapping_key));
    let mut encrypted_key = vec![0; 40];
    encrypted_key.resize(40, 0);
    let cek = cek.to_vec();
    wrapping_key
        .wrap(&cek, &mut encrypted_key)
        .map_err(|e| anyhow!("failed to do AES wrapping: {e:?}"))?;

    let point = p521::EncodedPoint::from(encrypter_secret.public_key());
    let epk_x = point
        .x()
        .ok_or(anyhow!("invalid public key: without coordinate X"))?;
    let epk_y = point
        .y()
        .ok_or(anyhow!("invalid public key: without coordinate Y"))?;
    let epk_x = URL_SAFE_NO_PAD.encode(epk_x);
    let epk_y = URL_SAFE_NO_PAD.encode(epk_y);
    let protected = ProtectedHeader {
        alg: ECDH_ES_A256KW.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: json!({
            "epk": {
                "crv": P521_CURVE,
                "kty": EC_KTY,
                "x": epk_x,
                "y": epk_y
            }
        })
        .as_object()
        .unwrap()
        .clone(),
    };

    // 3. Encrypt content with CEK
    let mut cek_cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));

    let iv = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let aad = protected.generate_aad().context("Generate JWE AAD")?;

    let tag = cek_cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    Ok(Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}

pub fn jwe(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> Result<Response> {
    match tee_pub_key {
        TeePubKey::RSA { alg, k_mod, k_exp } => match &alg[..] {
            #[allow(deprecated)]
            RSA1_5_ALGORITHM => rsa_1v15(k_mod, k_exp, payload_data),
            RSA_OAEP256_ALGORITHM => rsa_oaep256(k_mod, k_exp, payload_data),
            others => bail!("algorithm {others} is not supported"),
        },
        TeePubKey::EC { crv, alg, x, y } => match (&crv[..], &alg[..]) {
            (P256_CURVE, ECDH_ES_A256KW) => ecdh_es_a256kw_p256(x, y, payload_data),
            (P521_CURVE, ECDH_ES_A256KW) => ecdh_es_a256kw_p521(x, y, payload_data),
            (crv, alg) => bail!("curve {crv} and algorithm {alg} is not supported"),
        },
    }
}

#[cfg(test)]
mod tests {
    use core::assert_eq;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use josekit::jwe::{
        alg::{ecdh_es::EcdhEsJweAlgorithm::EcdhEsA256kw, rsaes::RsaesJweAlgorithm::RsaOaep256},
        JweContext, JweHeader, JweHeaderSet,
    };
    use kbs_types::TeePubKey;
    use openssl::rsa::Rsa;
    use p256::pkcs8::EncodePrivateKey;

    use crate::jwe::{
        AES_GCM_256_ALGORITHM, ECDH_ES_A256KW, P256_CURVE, P521_CURVE, RSA1_5_ALGORITHM,
        RSA_OAEP256_ALGORITHM,
    };

    use super::jwe;

    #[allow(deprecated)]
    #[test]
    fn jwe_rsav15_compatibility() {
        let test_data = b"this is a test data";

        // Generate a 4096-bit RSA key pair
        let rsa_key = Rsa::generate(4096).unwrap();
        let k_mod = URL_SAFE_NO_PAD.encode(rsa_key.n().to_vec());
        let k_exp = URL_SAFE_NO_PAD.encode(rsa_key.e().to_vec());
        let tee_key = TeePubKey::RSA {
            alg: RSA1_5_ALGORITHM.into(),
            k_mod,
            k_exp,
        };

        // Generate a JWE response
        let response = jwe(tee_key, test_data.to_vec()).unwrap();
        let response_string = serde_json::to_string(&response).unwrap();

        // Decrypt with josekit crate
        let decrypter = josekit::jwe::alg::rsaes::RsaesJweAlgorithm::Rsa1_5
            .decrypter_from_pem(rsa_key.private_key_to_pem().unwrap())
            .unwrap();
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption(AES_GCM_256_ALGORITHM);
        let context = JweContext::new();
        let (decrypted_data, header) = context
            .deserialize_json(&response_string, &decrypter)
            .unwrap();
        assert_eq!(decrypted_data, test_data);

        let mut jwe_header = JweHeader::new();
        jwe_header
            .set_claim("alg", Some(RSA1_5_ALGORITHM.into()))
            .unwrap();
        jwe_header
            .set_claim("enc", Some(AES_GCM_256_ALGORITHM.into()))
            .unwrap();
        assert_eq!(header, jwe_header);
    }

    #[test]
    fn jwe_rsa_oaep_compatibility() {
        let test_data = b"this is a test data";

        // Generate a 4096-bit RSA key pair
        let rsa_key = Rsa::generate(4096).unwrap();
        let k_mod = URL_SAFE_NO_PAD.encode(rsa_key.n().to_vec());
        let k_exp = URL_SAFE_NO_PAD.encode(rsa_key.e().to_vec());
        let tee_key = TeePubKey::RSA {
            alg: RSA_OAEP256_ALGORITHM.into(),
            k_mod,
            k_exp,
        };

        // Generate a JWE response
        let response = jwe(tee_key, test_data.to_vec()).unwrap();
        let response_string = serde_json::to_string(&response).unwrap();

        // Decrypt with josekit crate
        let decrypter = RsaOaep256
            .decrypter_from_pem(rsa_key.private_key_to_pem().unwrap())
            .unwrap();
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption(AES_GCM_256_ALGORITHM);
        let context = JweContext::new();
        let (decrypted_data, header) = context
            .deserialize_json(&response_string, &decrypter)
            .unwrap();
        assert_eq!(decrypted_data, test_data);

        let mut jwe_header = JweHeader::new();
        jwe_header
            .set_claim("alg", Some(RSA_OAEP256_ALGORITHM.into()))
            .unwrap();
        jwe_header
            .set_claim("enc", Some(AES_GCM_256_ALGORITHM.into()))
            .unwrap();
        assert_eq!(header, jwe_header);
    }

    #[test]
    fn jwe_ecp256_compatibility() {
        let test_data = b"this is a test data";

        // Generate a EC key pair
        let mut rng = rand::thread_rng();
        let private_key = p256::SecretKey::random(&mut rng);
        let point = p256::EncodedPoint::from(private_key.public_key());
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        let x = URL_SAFE_NO_PAD.encode(x);
        let y = URL_SAFE_NO_PAD.encode(y);

        let tee_key = TeePubKey::EC {
            crv: P256_CURVE.into(),
            alg: ECDH_ES_A256KW.into(),
            x,
            y,
        };

        // Generate a JWE response
        let response = jwe(tee_key, test_data.to_vec()).unwrap();
        let response_string = serde_json::to_string(&response).unwrap();

        let mut header = JweHeaderSet::new();
        header.set_algorithm("ECDH-ES+A256KW", true);
        header.set_content_encryption("A256GCM", true);

        // Decrypt JWE with JOSEkit crate
        let private_key = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let decrypter = EcdhEsA256kw.decrypter_from_pem(&private_key).unwrap();

        let context = JweContext::new();
        let (decrypted_data, _) = context
            .deserialize_json(&response_string, &decrypter)
            .unwrap();
        assert_eq!(decrypted_data, test_data);
    }

    #[test]
    fn jwe_ecp521_compatibility() {
        let test_data = b"this is a test data";

        // Generate a EC key pair
        let mut rng = rand::thread_rng();
        let private_key = p521::SecretKey::random(&mut rng);
        let point = p521::EncodedPoint::from(private_key.public_key());
        let x = point.x().unwrap();
        let y = point.y().unwrap();
        let x = URL_SAFE_NO_PAD.encode(x);
        let y = URL_SAFE_NO_PAD.encode(y);

        let tee_key = TeePubKey::EC {
            crv: P521_CURVE.into(),
            alg: ECDH_ES_A256KW.into(),
            x,
            y,
        };

        // Generate a JWE response
        let response = jwe(tee_key, test_data.to_vec()).unwrap();
        let response_string = serde_json::to_string(&response).unwrap();

        let mut header = JweHeaderSet::new();
        header.set_algorithm("ECDH-ES+A256KW", true);
        header.set_content_encryption("A256GCM", true);

        // Decrypt JWE with JOSEkit crate
        let private_key = private_key
            .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
            .unwrap();
        let decrypter = EcdhEsA256kw.decrypter_from_pem(&private_key).unwrap();

        let context = JweContext::new();
        let (decrypted_data, _) = context
            .deserialize_json(&response_string, &decrypter)
            .unwrap();
        assert_eq!(decrypted_data, test_data);
    }
}
