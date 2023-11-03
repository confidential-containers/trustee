// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::token::AttestationTokenVerifier;
use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::signature::Verifier;
use serde_json::Value;

#[derive(Default)]
pub struct CoCoAttestationTokenVerifier {}

impl AttestationTokenVerifier for CoCoAttestationTokenVerifier {
    fn verify(&self, token: String) -> Result<String> {
        let split_token: Vec<&str> = token.split('.').collect();
        if !split_token.len() == 3 {
            bail!("Illegal JWT format")
        }

        let header = URL_SAFE_NO_PAD.decode(split_token[0])?;
        let claims = URL_SAFE_NO_PAD.decode(split_token[1])?;
        let signature = URL_SAFE_NO_PAD.decode(split_token[2])?;

        let header_value = serde_json::from_slice::<Value>(&header)?;
        let claims_value = serde_json::from_slice::<Value>(&claims)?;

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let Some(exp) = claims_value["exp"].as_i64() else {
            bail!("token expiration unset");
        };
        if exp < now {
            bail!("token expired");
        }
        if let Some(nbf) = claims_value["nbf"].as_i64() {
            if nbf > now {
                bail!("before validity");
            }
        }

        let jwk_value = claims_value["jwk"].as_object().ok_or_else(|| anyhow!("CoCo Attestation Token Claims must contain public key (JWK format) to verify signature"))?;
        let jwk = serde_json::to_string(&jwk_value)?;
        let payload = format!("{}.{}", &split_token[0], &split_token[1])
            .as_bytes()
            .to_vec();

        match header_value["alg"].as_str() {
            Some("RS384") => rs384_verify(&payload, &signature, &jwk)?,
            None => {
                bail!("Miss `alg` in JWT header")
            }
            _ => {
                bail!("Unsupported JWT algrithm")
            }
        }

        Ok(serde_json::to_string(&claims_value)?)
    }
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Clone, Debug)]
struct RsaJWK {
    kty: String,
    alg: String,
    n: String,
    e: String,
}

fn rs384_verify(payload: &[u8], signature: &[u8], jwk: &str) -> Result<()> {
    let jwk = serde_json::from_str::<RsaJWK>(jwk)?;
    if jwk.alg != *"RS384" {
        bail!("Unmatched RSA JWK alg");
    }

    let pkcs1v15_signature = rsa::pkcs1v15::Signature::try_from(signature)?;

    let n = rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.n)?);
    let e = rsa::BigUint::from_bytes_be(&URL_SAFE_NO_PAD.decode(&jwk.e)?);
    let rsa_public_key = rsa::RsaPublicKey::new(n, e)?;
    let verify_key = rsa::pkcs1v15::VerifyingKey::<rsa::sha2::Sha384>::new(rsa_public_key);

    verify_key
        .verify(payload, &pkcs1v15_signature)
        .map_err(|e| anyhow!("RS384 verify failed: {e}"))
}
