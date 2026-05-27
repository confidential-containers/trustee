// Copyright (c) 2026 Trustee contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Experimental Post-Quantum Cryptography extension for the KBS
//! resource-response JWE path.
//!
//! Implements `ML-KEM-768+A192KW` per draft-ietf-jose-pqc-kem-05.
//!
//! Wire format is not finalized — the IETF draft is in WG-adopted
//! Standards Track but not yet RFC. The KDF FixedInfo encoding (X input
//! to KMAC256) is underspecified by the draft; we follow the RFC 7518
//! §4.6.2 ConcatKDF precedent, omitting PartyUInfo/PartyVInfo as the PQ
//! draft directs. Verify against reference implementations and test
//! vectors when those emerge.

use aes_gcm::{
    aead::{AeadMutInPlace, OsRng},
    Aes256Gcm, KeyInit, Nonce,
};
use aes_kw::{KeyInit as AesKwKeyInit, KwAes192};
use anyhow::{bail, anyhow, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{ProtectedHeader, Response};
use ml_kem::{Encapsulate, EncapsulationKey, Key, MlKem768};
use rsa::rand_core::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3_kmac::Kmac256;

/// `kty` value for the Algorithm Key Pair (AKP) key type per
/// draft-ietf-jose-pqc-kem-05 §10.
pub const AKP_KTY: &str = "AKP";

/// Algorithm identifier for ML-KEM-768 with AES-192 key wrap.
pub const ML_KEM_768_A192KW_ALGORITHM: &str = "ML-KEM-768+A192KW";

/// AES-256-GCM content encryption, matches existing classical paths.
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

/// ML-KEM-768 encapsulation-key length in bytes (FIPS 203).
const ML_KEM_768_ENCAP_KEY_LEN: usize = 1184;

/// AKP public key as received from a TEE client, per the JWK
/// representation in draft-ietf-jose-pqc-kem-05 §10.
///
/// Defined locally rather than as a new `kbs_types::TeePubKey` variant
/// while the wire format stabilises. When the prototype proves out, this
/// should be upstreamed to the `kbs-types` crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AkpPubKey {
    /// JWK key type — MUST be `"AKP"`.
    pub kty: String,
    /// Algorithm identifier, e.g. `"ML-KEM-768+A192KW"`.
    pub alg: String,
    /// Base64url-encoded ML-KEM encapsulation key.
    /// For ML-KEM-768 this decodes to 1184 bytes.
    #[serde(rename = "pub")]
    pub public_key: String,
}


/// KMAC256-based KDF per draft-ietf-jose-pqc-kem-05 §5.1.
///
/// `KMAC256(K = shared_secret, X = AlgorithmID || SuppPubInfo,
///          L = out_len_bytes·8 bits, S = "")`
///
/// AlgorithmID = 4-byte BE length(alg) || alg.
/// SuppPubInfo = 4-byte BE keydatalen-in-bits.
/// PartyUInfo / PartyVInfo are intentionally excluded per the draft.
fn kmac256_kdf(shared_secret: &[u8], alg: &str, out_len_bytes: usize) -> Result<Vec<u8>> {
    let alg_bytes = alg.as_bytes();
    let alg_len = (alg_bytes.len() as u32).to_be_bytes();
    let keydatalen_bits = ((out_len_bytes * 8) as u32).to_be_bytes();

    let mut x = Vec::with_capacity(4 + alg_bytes.len() + 4);
    x.extend_from_slice(&alg_len);
    x.extend_from_slice(alg_bytes);
    x.extend_from_slice(&keydatalen_bits);

    let mut kmac = Kmac256::new(shared_secret, b"")
        .map_err(|e| anyhow!("KMAC256 init failed: {e:?}"))?;
    kmac.update(&x);
    let mut out = vec![0u8; out_len_bytes];
    kmac.finalize_into(&mut out);
    Ok(out)
}

/// Encrypt `payload_data` for an AKP/ML-KEM-768 recipient per
/// draft-ietf-jose-pqc-kem-05.
pub fn ml_kem_768_a192kw(pub_key_b64: &str, mut payload_data: Vec<u8>) -> Result<Response> {
    // 1. Decode and parse the recipient's encapsulation key.
    let pub_key_bytes = URL_SAFE_NO_PAD
        .decode(pub_key_b64)
        .context("base64 decode AKP pub_key failed")?;
    if pub_key_bytes.len() != ML_KEM_768_ENCAP_KEY_LEN {
        bail!(
            "ML-KEM-768 encapsulation key has wrong length: got {}, expected {}",
            pub_key_bytes.len(),
            ML_KEM_768_ENCAP_KEY_LEN,
        );
    }
    let ek_typed: &Key<EncapsulationKey<MlKem768>> = pub_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("ML-KEM-768 encapsulation key array conversion failed"))?;
    let encap_key = EncapsulationKey::<MlKem768>::new(ek_typed)
        .map_err(|e| anyhow!("invalid ML-KEM-768 encapsulation key: {e:?}"))?;

    // 2. Encapsulate → (KEM ciphertext, 32-byte shared secret). Uses OS RNG
    // internally (ml-kem `getrandom` feature).
    let (kem_ciphertext, shared_secret) = encap_key.encapsulate();

    // 3. Derive the 24-byte AES-192 wrapping key from the shared secret.
    let kwk = kmac256_kdf(shared_secret.as_slice(), ML_KEM_768_A192KW_ALGORITHM, 24)?;
    let kwk: [u8; 24] = kwk
        .try_into()
        .map_err(|_| anyhow!("KDF output not 24 bytes"))?;

    // 4. Generate a 32-byte CEK and wrap it under the KWK.
    let cek = Aes256Gcm::generate_key(&mut OsRng);
    let wrapper = KwAes192::new(&kwk.into());
    let mut encrypted_key = vec![0u8; 40]; // 32-byte CEK + 8-byte AES-KW integrity check
    wrapper
        .wrap_key(&cek, &mut encrypted_key)
        .map_err(|e| anyhow!("AES-KW failed: {e:?}"))?;

    // 5. Protected header carries the KEM ciphertext in the `ek` parameter
    // per draft-ietf-jose-pqc-kem §6.2.
    let ek_b64 = URL_SAFE_NO_PAD.encode(kem_ciphertext.as_slice());
    let protected = ProtectedHeader {
        alg: ML_KEM_768_A192KW_ALGORITHM.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: json!({ "ek": ek_b64 })
            .as_object()
            .unwrap()
            .clone(),
    };

    // 6. Encrypt payload with AES-256-GCM under the CEK; AAD per RFC 7516.
    let mut cipher = Aes256Gcm::new(&cek);
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from_slice(&iv);
    let aad = protected.generate_aad().context("Generate JWE AAD")?;
    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES-GCM encrypt failed: {e}"))?;

    Ok(Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: None,
        tag: tag.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::aead::generic_array::GenericArray;
    use ml_kem::{kem::KeyExport, Decapsulate, Kem};

    #[test]
    fn ml_kem_768_a192kw_roundtrip() {
        // Fresh ML-KEM-768 keypair.
        let (decap_key, encap_key) = MlKem768::generate_keypair();
        let pub_key_b64 = URL_SAFE_NO_PAD.encode(encap_key.to_bytes());

        let payload = b"hello post-quantum world".to_vec();
        let response = ml_kem_768_a192kw(&pub_key_b64, payload.clone()).expect("encrypt");

        // Recipient: pull KEM ciphertext out of `ek`, decapsulate, derive KWK,
        // unwrap CEK, decrypt payload.
        let ek_b64 = response
            .protected
            .other_fields
            .get("ek")
            .and_then(|v| v.as_str())
            .expect("ek header present");
        let kem_ct_bytes = URL_SAFE_NO_PAD.decode(ek_b64).expect("decode ek");
        let shared_secret = decap_key
            .decapsulate_slice(&kem_ct_bytes)
            .expect("decapsulate");

        let kwk =
            kmac256_kdf(shared_secret.as_slice(), ML_KEM_768_A192KW_ALGORITHM, 24).expect("kdf");
        let kwk: [u8; 24] = kwk.try_into().unwrap();
        let unwrapper = KwAes192::new(&kwk.into());
        let mut cek = vec![0u8; 32];
        unwrapper
            .unwrap_key(&response.encrypted_key, &mut cek)
            .expect("unwrap CEK");

        let mut cipher = Aes256Gcm::new(GenericArray::from_slice(&cek));
        let nonce = Nonce::from_slice(&response.iv);
        let aad = response.protected.generate_aad().expect("aad");
        let mut buf = response.ciphertext.clone();
        cipher
            .decrypt_in_place_detached(nonce, &aad, &mut buf, response.tag.as_slice().into())
            .expect("decrypt payload");

        assert_eq!(buf, payload);
    }

    #[test]
    fn protected_header_carries_ek_and_correct_alg() {
        let (_decap_key, encap_key) = MlKem768::generate_keypair();
        let pub_key_b64 = URL_SAFE_NO_PAD.encode(encap_key.to_bytes());
        let response = ml_kem_768_a192kw(&pub_key_b64, b"x".to_vec()).expect("encrypt");
        assert_eq!(response.protected.alg, ML_KEM_768_A192KW_ALGORITHM);
        assert_eq!(response.protected.enc, AES_GCM_256_ALGORITHM);
        assert!(response.protected.other_fields.contains_key("ek"));
    }

    #[test]
    fn rejects_wrong_length_pub_key() {
        let bad = URL_SAFE_NO_PAD.encode([0u8; 100]);
        let err = ml_kem_768_a192kw(&bad, b"x".to_vec()).expect_err("should reject");
        assert!(err.to_string().contains("wrong length"));
    }

    #[test]
    fn akp_pub_key_deserializes_from_jwk() {
        let json = serde_json::json!({
            "kty": "AKP",
            "alg": "ML-KEM-768+A192KW",
            "pub": "AAAAAAAAAAAAAAAAAA",
        });
        let key: AkpPubKey = serde_json::from_value(json).expect("deserialize");
        assert_eq!(key.kty, AKP_KTY);
        assert_eq!(key.alg, ML_KEM_768_A192KW_ALGORITHM);
        assert_eq!(key.public_key, "AAAAAAAAAAAAAAAAAA");
    }
}
