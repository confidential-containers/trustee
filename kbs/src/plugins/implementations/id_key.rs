// Copyright (c) 2025 by Red Hat.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::super::plugin_manager::ClientPlugin;
use actix_web::http::Method;
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit};
use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use generic_array::GenericArray;
use openssl::{
    pkey::Private,
    rsa::{Padding, Rsa},
};
use p384::{ecdh, PublicKey, SecretKey};
use serde::Deserialize;
use sha2::Sha256;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct IdKeyConfig;

pub struct IdKey {
    idkey_non_hsm: Rsa<Private>,
    ecdh_secret: SecretKey,
}

impl TryFrom<IdKeyConfig> for IdKey {
    type Error = anyhow::Error;

    fn try_from(_value: IdKeyConfig) -> anyhow::Result<Self> {
        Self::new()
    }
}

#[async_trait::async_trait]
impl ClientPlugin for IdKey {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with '/'")?;

        match *method {
            Method::POST => {
                let plain = URL_SAFE_NO_PAD
                    .decode(path)
                    .context("invalid id-key path")?;

                self.encrypt(plain)
            }
            Method::GET => match path {
                "ecdh-pub-sec1" => Ok(self.ecdh_pubkey_sec1()),
                _ => {
                    let (public_key, iv) = ecdh_iv(query.to_string())?;

                    let wrapped = URL_SAFE_NO_PAD.decode(path).context("invalid path")?;
                    let encrypted = self.ecdh_unwrap(wrapped, public_key, iv)?;
                    let decrypted = self.decrypt(encrypted)?;

                    Ok(decrypted)
                }
            },
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        match method {
            &Method::POST => Ok(true),
            _ => Ok(false),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        match *method {
            Method::GET => Ok(true),
            _ => Ok(false),
        }
    }
}

impl IdKey {
    pub fn new() -> Result<Self> {
        Ok(Self {
            idkey_non_hsm: Rsa::generate(2048).context("unable to create ID key")?,
            ecdh_secret: SecretKey::random(&mut rand::thread_rng()),
        })
    }

    fn encrypt(&self, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let encrypted = {
            let mut d = [0u8; 256];
            let sz = self
                .idkey_non_hsm
                .public_encrypt(&bytes, &mut d, Padding::PKCS1)
                .context("unable to decrypt key")?;

            Vec::from(&d[..sz])
        };

        Ok(URL_SAFE_NO_PAD.encode(encrypted).into())
    }

    fn ecdh_pubkey_sec1(&self) -> Vec<u8> {
        self.ecdh_secret.public_key().to_sec1_bytes().to_vec()
    }

    fn ecdh_unwrap(
        &self,
        wrapped: Vec<u8>,
        ec_public_key: PublicKey,
        iv: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let shared = ecdh::diffie_hellman(
            self.ecdh_secret.to_nonzero_scalar(),
            ec_public_key.as_affine(),
        );
        let mut sha_bytes = [0u8; 32];

        let hkdf = shared.extract::<Sha256>(None);
        if hkdf.expand(&[], &mut sha_bytes).is_err() {
            return Err(anyhow!("unable to get ECDH shared SHA hash"));
        }

        let key = Key::<Aes256Gcm>::from_slice(&sha_bytes);
        let aes = Aes256Gcm::new(key);

        let encrypted = match aes.decrypt(GenericArray::from_slice(iv.as_slice()), wrapped.as_ref())
        {
            Ok(e) => e,
            Err(_) => {
                return Err(anyhow!(
                    "unable to unwrap encrypted secret with shared AES-GCM key"
                ))
            }
        };

        Ok(encrypted)
    }

    fn decrypt(&self, encrypted: Vec<u8>) -> Result<Vec<u8>> {
        let mut d = [0u8; 256];
        let sz = self
            .idkey_non_hsm
            .private_decrypt(&encrypted, &mut d, Padding::PKCS1)
            .context("unable to decrypt key")?;

        Ok(Vec::from(&d[..sz]))
    }
}

fn ecdh_iv(query: String) -> Result<(PublicKey, Vec<u8>)> {
    let subs: Vec<&str> = query.split('&').collect();
    if subs.len() != 2 {
        bail!("invalid query");
    }

    let public_key = {
        let bytes = parse_val("ecdh-pubkey", &subs)?;
        PublicKey::from_sec1_bytes(&bytes)
            .context("public key cannot be derived from SEC1 bytes")?
    };

    let iv = parse_val("iv", &subs)?;

    Ok((public_key, iv))
}

fn parse_val(key: &str, subs: &Vec<&str>) -> Result<Vec<u8>> {
    for substr in subs {
        let kv: Vec<&str> = substr.split('=').collect();
        if kv.len() != 2 {
            bail!("invalid query");
        }

        if kv[0] == key {
            let bytes = URL_SAFE_NO_PAD.decode(kv[1]).context("invalid query")?;

            return Ok(bytes);
        }
    }

    Err(anyhow!("invalid query"))
}
