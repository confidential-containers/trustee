// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::rand::Rng;
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use kbs_types::{Response, TeePubKey};
use local_fs::{LocalFs, LocalFsRepoDesc};
use num_traits::Num;
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPublicKey};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::RwLock;

mod local_fs;

const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

/// Interface of a `Repository`.
#[async_trait::async_trait]
pub trait Repository {
    /// Read secret resource from repository.
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>>;

    /// Write secret resource into repository
    async fn write_secret_resource(
        &mut self,
        resource_desc: ResourceDesc,
        data: &[u8],
    ) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct ResourceDesc {
    pub repository_name: String,
    pub resource_type: String,
    pub resource_tag: String,
}

#[derive(Deserialize, Debug, Clone, EnumString)]
pub enum RepositoryType {
    LocalFs,
}

impl RepositoryType {
    pub fn to_repository(
        &self,
        repo_desc: &Option<Value>,
    ) -> Result<Arc<RwLock<dyn Repository + Send + Sync>>> {
        match self {
            RepositoryType::LocalFs => {
                let desc = match repo_desc {
                    Some(d) => serde_json::from_value::<LocalFsRepoDesc>(d.clone())?,
                    None => local_fs::LocalFsRepoDesc::default(),
                };

                // Create repository dir.
                if !Path::new(&desc.dir_path).exists() {
                    fs::create_dir_all(&desc.dir_path)?;
                }
                // Create default repo.
                if !Path::new(&format!("{}/default", &desc.dir_path)).exists() {
                    fs::create_dir_all(format!("{}/default", &desc.dir_path))?;
                }

                Ok(Arc::new(RwLock::new(LocalFs::new(desc)?))
                    as Arc<RwLock<dyn Repository + Send + Sync>>)
            }
        }
    }
}

pub(crate) async fn get_secret_resource(
    tee_pub_key: TeePubKey,
    repository: &Arc<RwLock<dyn Repository + Send + Sync>>,
    resource_desc: ResourceDesc,
) -> Result<Response> {
    if tee_pub_key.alg != *RSA_ALGORITHM {
        return Err(anyhow!("Unsupported TEE Pub Key type or algorithm"));
    }

    let resource_byte = repository
        .read()
        .await
        .read_secret_resource(resource_desc)
        .await
        .map_err(|e| anyhow!("Read secret resource from repository failed: {:?}", e))?;

    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let encrypted_resource_payload = cipher
        .encrypt(nonce, resource_byte.as_slice())
        .map_err(|e| anyhow!("AES encrypt Resource payload failed: {:?}", e))?;

    let n = BigUint::from_str_radix(&tee_pub_key.k_mod, 10)
        .map_err(|e| anyhow!("Parse TEE pubkey modulus failed: {:?}", e))?;
    let e = BigUint::from_str_radix(&tee_pub_key.k_exp, 10)
        .map_err(|e| anyhow!("Parse TEE pubkey exponent failed: {:?}", e))?;

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
        ciphertext: base64::encode_config(encrypted_resource_payload, base64::URL_SAFE_NO_PAD),
        tag: "".to_string(),
    })
}

pub(crate) async fn set_secret_resource(
    repository: &Arc<RwLock<dyn Repository + Send + Sync>>,
    resource_desc: ResourceDesc,
    data: &[u8],
) -> Result<()> {
    repository
        .write()
        .await
        .write_secret_resource(resource_desc, data)
        .await
}
