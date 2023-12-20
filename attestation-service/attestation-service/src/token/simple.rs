// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha384;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde_json::{json, Value};

use crate::token::{AttestationTokenBroker, AttestationTokenConfig};

const ISSUER_NAME: &str = "CoCo-Attestation-Service";
const RSA_KEY_BITS: usize = 2048;
const SIMPLE_TOKEN_ALG: &str = "RS384";

pub struct SimpleAttestationTokenBroker {
    private_key: RsaPrivateKey,
    config: AttestationTokenConfig,
}

impl SimpleAttestationTokenBroker {
    pub fn new(config: AttestationTokenConfig) -> Result<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, RSA_KEY_BITS)?;

        Ok(Self {
            private_key,
            config,
        })
    }
}

impl SimpleAttestationTokenBroker {
    fn rs384_sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::<Sha384>::new(self.private_key.clone());
        let signature = signing_key.sign_with_rng(&mut rng, payload);
        Ok(signature.to_bytes().to_vec())
    }
}

impl AttestationTokenBroker for SimpleAttestationTokenBroker {
    fn issue(&self, custom_claims: Value) -> Result<String> {
        let header_value = json!({
            "typ": "JWT",
            "alg": SIMPLE_TOKEN_ALG,
        });
        let header_string = serde_json::to_string(&header_value)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_string.as_bytes());

        let now = time::OffsetDateTime::now_utc();
        let exp = now + time::Duration::minutes(self.config.duration_min);

        let id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut claims = json!({
            "iss": ISSUER_NAME,
            "iat": now.unix_timestamp(),
            "jti": id,
            "jwk": serde_json::from_str::<Value>(&self.pubkey_jwks()?)?["keys"][0].clone(),
            "nbf": now.unix_timestamp(),
            "exp": exp.unix_timestamp(),
        })
        .as_object()
        .ok_or_else(|| anyhow!("Internal Error: generate claims failed"))?
        .clone();

        claims.extend(
            custom_claims
                .as_object()
                .ok_or_else(|| anyhow!("Illegal token custom claims"))?
                .to_owned(),
        );

        let claims_value = Value::Object(claims);
        let claims_string = serde_json::to_string(&claims_value)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

        let signature_payload = format!("{header_b64}.{claims_b64}");
        let signature = self.rs384_sign(signature_payload.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        let token = format!("{signature_payload}.{signature_b64}");

        Ok(token)
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let pubkey = self.private_key.to_public_key();
        let n = pubkey.n().to_bytes_be();
        let e = pubkey.e().to_bytes_be();

        let jwk = json!({
            "kty": "RSA",
            "alg": SIMPLE_TOKEN_ALG,
            "n": URL_SAFE_NO_PAD.encode(n),
            "e": URL_SAFE_NO_PAD.encode(e),
        });
        let jwks = json!({
            "keys": vec![jwk],
        });

        Ok(serde_json::to_string(&jwks)?)
    }
}
