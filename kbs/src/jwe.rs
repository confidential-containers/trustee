// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{ProtectedHeader, Response, TeePubKey};
use openssl::bn::BigNum;
use openssl::{
    encrypt,
    pkey::PKey,
    rsa::{self, Rsa},
};
use rand::{rngs::OsRng, Rng};

const RSA_ALGORITHM: &str = "RSA-OAEP";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

fn encrypt_plain(
    k_mod: &[u8],
    k_exp: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let n = BigNum::from_slice(k_mod)?;
    let e = BigNum::from_slice(k_exp)?;
    let rsa_pubkey = Rsa::from_public_components(n, e)?;
    let pkey = PKey::from_rsa(rsa_pubkey)?;

    let mut encrypter = encrypt::Encrypter::new(&pkey)?;
    encrypter.set_rsa_padding(rsa::Padding::PKCS1_OAEP)?;
    let buffer_len = encrypter.encrypt_len(plain)?;
    let mut encrypted = vec![0; buffer_len];
    let encrypted_len = encrypter.encrypt(plain, &mut encrypted)?;
    encrypted.truncate(encrypted_len);

    Ok(encrypted.to_vec())
}

pub fn jwe(tee_pub_key: TeePubKey, mut payload_data: Vec<u8>) -> Result<Response> {
    let TeePubKey::RSA { alg, k_mod, k_exp } = tee_pub_key else {
        bail!("Only RSA key is support for TEE pub key")
    };

    if alg != *RSA_ALGORITHM {
        bail!("algorithm is not {RSA_ALGORITHM} but {alg}");
    }

    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let mut cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let protected = ProtectedHeader {
        alg: RSA_ALGORITHM.to_string(),
        enc: AES_GCM_256_ALGORITHM.to_string(),
        other_fields: BTreeMap::new(),
    };

    let aad = protected.generate_aad().context("Generate JWE AAD")?;

    let tag = cipher
        .encrypt_in_place_detached(nonce, &aad, &mut payload_data)
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {e}"))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(k_mod)
        .context("base64 decode k_mod failed")?;
    let k_exp = URL_SAFE_NO_PAD
        .decode(k_exp)
        .context("base64 decode k_exp failed")?;
    let encrypted_key = encrypt_plain(&k_mod, &k_exp, &aes_sym_key)
        .context("Encrypting AES key with RSA key failed")?;

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
    use core::assert_eq;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use josekit::jwe::{alg::rsaes::RsaesJweAlgorithm::RsaOaep, JweContext, JweHeader};
    use kbs_types::TeePubKey;
    use openssl::rsa::Rsa;

    use super::jwe;

    #[test]
    fn jwe_compability() {
        let test_data = b"this is a test data";

        // Generate a 4096-bit RSA key pair
        let rsa_key = Rsa::generate(4096).unwrap();
        let k_mod = URL_SAFE_NO_PAD.encode(rsa_key.n().to_vec());
        let k_exp = URL_SAFE_NO_PAD.encode(rsa_key.e().to_vec());
        let tee_key = TeePubKey::RSA {
            alg: crate::jwe::RSA_ALGORITHM.into(),
            k_mod,
            k_exp,
        };

        // Generate a JWE response
        let response = jwe(tee_key, test_data.to_vec()).unwrap();
        let response_string = serde_json::to_string(&response).unwrap();

        // Decrypt with josekit crate
        let decrypter = RsaOaep
            .decrypter_from_pem(rsa_key.private_key_to_pem().unwrap())
            .unwrap();
        let mut header = JweHeader::new();
        header.set_token_type("JWT");
        header.set_content_encryption("A256GCM");
        let context = JweContext::new();
        let (decrypted_data, header) = context
            .deserialize_json(&response_string, &decrypter)
            .unwrap();
        assert_eq!(decrypted_data, test_data);

        let mut jwe_header = JweHeader::new();
        jwe_header
            .set_claim("alg", Some("RSA-OAEP".into()))
            .unwrap();
        jwe_header.set_claim("enc", Some("A256GCM".into())).unwrap();
        assert_eq!(header, jwe_header);
    }
}
