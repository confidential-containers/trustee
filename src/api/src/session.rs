// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie, Expiration,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, bail, Result};
use as_types::AttestationResults;
use kbs_types::{Request, Response, Tee, TeePubKey};
use rand::{thread_rng, Rng};
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPublicKey};
use semver::Version;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

const RSA_KEY_TYPE: &str = "RSA";
const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

fn nonce() -> Result<String> {
    let mut nonce: Vec<u8> = vec![0; 32];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(base64::encode_config(&nonce, base64::STANDARD))
}

#[allow(dead_code)]
pub(crate) struct Session<'a> {
    cookie: Cookie<'a>,
    nonce: String,
    tee: Tee,
    tee_extra_params: Option<String>,
    tee_pub_key: Option<TeePubKey>,
    attestation_results: Option<AttestationResults>,
}

#[allow(dead_code)]
impl<'a> Session<'a> {
    pub fn from_request(req: &Request, timeout: i64) -> Result<Self> {
        let version = Version::parse(&req.version).map_err(anyhow::Error::from)?;
        if !crate::VERSION_REQ.matches(&version) {
            return Err(anyhow!("Invalid Request version {}", req.version));
        }
        let id = Uuid::new_v4().as_simple().to_string();
        let tee_extra_params = if req.extra_params.is_empty() {
            None
        } else {
            Some(req.extra_params.clone())
        };

        let cookie = Cookie::build(KBS_SESSION_ID, id)
            .expires(OffsetDateTime::now_utc() + Duration::minutes(timeout))
            .finish();

        Ok(Session {
            cookie,
            nonce: nonce()?,
            tee: req.tee.clone(),
            tee_extra_params,
            tee_pub_key: None,
            attestation_results: None,
        })
    }

    pub fn id(&self) -> &str {
        self.cookie.value()
    }

    pub fn cookie(&self) -> Cookie {
        self.cookie.clone()
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn tee(&self) -> Tee {
        self.tee.clone()
    }

    pub fn tee_public_key(&self) -> Option<TeePubKey> {
        self.tee_pub_key.clone()
    }

    pub fn is_authenticated(&self) -> bool {
        self.attestation_results
            .as_ref()
            .map_or(false, |a| a.allow())
    }

    pub fn is_expired(&self) -> bool {
        if let Some(Expiration::DateTime(time)) = self.cookie.expires() {
            return OffsetDateTime::now_utc() > time;
        }

        false
    }

    pub fn is_valid(&self) -> bool {
        self.is_authenticated() && !self.is_expired()
    }

    pub fn attestation_results(&self) -> Option<AttestationResults> {
        self.attestation_results.clone()
    }

    pub fn set_attestation_results(&mut self, attestation_results: AttestationResults) {
        self.attestation_results = Some(attestation_results)
    }

    pub fn set_tee_public_key(&mut self, key: TeePubKey) {
        self.tee_pub_key = Some(key)
    }

    pub fn to_jwe(&self, payload_data: Vec<u8>) -> Result<Response> {
        let tee_pub_key = self
            .tee_public_key()
            .ok_or_else(|| anyhow!("No TEE public Key"))?;
        if tee_pub_key.kty != *RSA_KEY_TYPE {
            bail!("TEE pub key has unsupported JWK key type (kty)");
        }
        if tee_pub_key.alg != *RSA_ALGORITHM {
            bail!("TEE pub key has unsupported JWK algorithm (alg)");
        }

        let mut rng = rand::thread_rng();

        let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
        let cipher = Aes256Gcm::new(&aes_sym_key);
        let iv = rng.gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&iv);
        let encrypted_payload_data = cipher
            .encrypt(nonce, payload_data.as_slice())
            .map_err(|e| anyhow!("AES encrypt Resource payload failed: {:?}", e))?;

        let k_mod = base64::decode_config(&tee_pub_key.k_mod, base64::URL_SAFE_NO_PAD)?;
        let n = BigUint::from_bytes_be(&k_mod);
        let k_exp = base64::decode_config(&tee_pub_key.k_exp, base64::URL_SAFE_NO_PAD)?;
        let e = BigUint::from_bytes_be(&k_exp);

        let rsa_pub_key = RsaPublicKey::new(n, e)
            .map_err(|e| anyhow!("Building RSA key from modulus and exponent failed: {:?}", e))?;
        let padding = PaddingScheme::new_pkcs1v15_encrypt();
        let sym_key: &[u8] = aes_sym_key.as_slice();
        let wrapped_sym_key = rsa_pub_key
            .encrypt(&mut rng, padding, sym_key)
            .map_err(|e| anyhow!("RSA encrypt sym key failed: {:?}", e))?;

        let protected_header = json!(
        {
           "alg": RSA_ALGORITHM.to_string(),
           "enc": AES_GCM_256_ALGORITHM.to_string(),
        });

        Ok(Response {
            protected: serde_json::to_string(&protected_header)?,
            encrypted_key: base64::encode_config(wrapped_sym_key, base64::URL_SAFE_NO_PAD),
            iv: base64::encode_config(iv, base64::URL_SAFE_NO_PAD),
            ciphertext: base64::encode_config(encrypted_payload_data, base64::URL_SAFE_NO_PAD),
            tag: "".to_string(),
        })
    }
}

pub(crate) struct SessionMap<'a> {
    pub sessions: RwLock<HashMap<String, Arc<Mutex<Session<'a>>>>>,
}

impl<'a> SessionMap<'a> {
    pub fn new() -> Self {
        SessionMap {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}
