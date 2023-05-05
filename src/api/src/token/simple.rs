// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::*;
use core::str::FromStr;
use ecdsa::sec1::ToEncodedPoint;
use elliptic_curve as ecdsa;
use jwt_simple::algorithms::{ECDSAP256KeyPairLike, ECDSAP256PublicKeyLike};
use jwt_simple::prelude::{Claims, Duration, ES256KeyPair};
use p256::NistP256;
use rcgen::{Certificate, CertificateParams};
use serde_json::{json, Value};

use crate::token::AttestationTokenBroker;

pub struct SimpleAttestationTokenBroker {
    key_pair: ES256KeyPair,
    cert: Vec<u8>,
}

impl SimpleAttestationTokenBroker {
    pub fn new() -> Result<Self> {
        let key_pair = ES256KeyPair::generate().with_key_id("simple");

        let rcgen_key_pair = rcgen::KeyPair::from_pem(&key_pair.to_pem()?)?;
        let mut cert_params = CertificateParams::new(vec!["CoCo-Attestation-Service".to_string()]);
        cert_params.key_pair = Some(rcgen_key_pair);
        let cert = Certificate::from_params(cert_params)?.serialize_der()?;

        Ok(Self { key_pair, cert })
    }
}

impl AttestationTokenBroker for SimpleAttestationTokenBroker {
    fn issue(&self, custom_claims: Value, duration_min: usize) -> Result<String> {
        let claims = Claims::with_custom_claims(
            custom_claims,
            Duration::from_mins(duration_min.try_into().unwrap()),
        );
        let token = self.key_pair.sign(claims)?;
        Ok(token)
    }

    fn verify(&self, token: String) -> Result<String> {
        let claims = self
            .key_pair
            .public_key()
            .verify_token::<Value>(&token, None)?;
        Ok(serde_json::to_string(&claims)?)
    }

    fn x509_certificate_chain(&self) -> Result<String> {
        let pubkey_pem = self.key_pair.public_key().to_pem()?;
        let ec_pubkey = ecdsa::PublicKey::<NistP256>::from_str(&pubkey_pem)
            .map_err(|e| anyhow!("Convert pem public key to ECDSA pubkey failed: {:?}", e))?
            .to_encoded_point(false);
        let ecdsa_x = ec_pubkey
            .x()
            .ok_or_else(|| anyhow!("Export ECDSA public key x failed"))?
            .as_slice()
            .to_vec();
        let ecdsa_y = ec_pubkey
            .y()
            .ok_or_else(|| anyhow!("Export ECDSA public key y failed"))?
            .as_slice()
            .to_vec();

        let jwk = json!({
            "kty": "EC",
            "crv": "P-256",
            "x": base64::encode_config(ecdsa_x, base64::URL_SAFE_NO_PAD),
            "y": base64::encode_config(ecdsa_y, base64::URL_SAFE_NO_PAD),
            "use": "sig",
            "kid": self.key_pair.key_id(),
            "x5c": vec![base64::encode_config(self.cert.clone(), base64::URL_SAFE_NO_PAD)],
        });
        let jwks = json!({
            "keys": vec![jwk],
        });

        Ok(serde_json::to_string(&jwks)?)
    }
}
