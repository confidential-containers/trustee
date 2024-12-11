// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use aes_gcm::{aead::AeadMutInPlace, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::{ProtectedHeader, Response, TeePubKey};
use rand::{rngs::OsRng, Rng};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};

const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

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
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(k_exp)
        .context("base64 decode k_exp failed")?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key =
        RsaPublicKey::new(n, e).context("Building RSA key from modulus and exponent failed")?;
    let sym_key: &[u8] = aes_sym_key.as_slice();
    let encrypted_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, sym_key)
        .context("RSA encrypt sym key failed")?;

    Ok(Response {
        protected,
        encrypted_key,
        iv: iv.into(),
        ciphertext: payload_data,
        aad: Some(aad),
        tag: tag.to_vec(),
    })
}
