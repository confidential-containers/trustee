// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{http::header::Header, web::Bytes};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use anyhow::{anyhow, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use kbs_types::{Response, TeePubKey};
use log::{error, info};
use rand::{rngs::OsRng, Rng};
use rsa::{BigUint, Pkcs1v15Encrypt, RsaPublicKey};
use serde::Deserialize;
use serde_json::{json, Deserializer, Value};

use crate::raise_error;

use super::*;

#[allow(unused_assignments)]
/// GET /resource/{repository}/{type}/{tag}
/// GET /resource/{type}/{tag}
pub(crate) async fn get_resource(
    request: HttpRequest,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
    #[cfg(feature = "as")] map: web::Data<SessionMap<'_>>,
    token_verifier: web::Data<Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>>,
) -> Result<HttpResponse> {
    #[allow(unused_mut)]
    let mut claims_option = None;
    #[cfg(feature = "as")]
    {
        claims_option = get_attest_claims_from_session(&request, map).await.ok();
    }
    let claims_str = if let Some(c) = claims_option {
        info!("Get pkey from session.");
        c
    } else {
        info!("Get pkey from auth header");
        get_attest_claims_from_header(&request, token_verifier).await?
    };
    let claims: Value = serde_json::from_str(&claims_str).map_err(|e| {
        Error::AttestationClaimsParseFailed(format!("illegal attestation claims: {e}"))
    })?;

    let pkey_value = claims
        .get("tee-pubkey")
        .ok_or(Error::AttestationClaimsParseFailed(String::from(
            "No `tee-pubkey` in the attestation claims",
        )))?;
    let pubkey = TeePubKey::deserialize(pkey_value).map_err(|e| {
        Error::AttestationClaimsParseFailed(format!("illegal attestation claims: {e}"))
    })?;

    let resource_description = ResourceDesc {
        repository_name: request
            .match_info()
            .get("repository")
            .unwrap_or("default")
            .to_string(),
        resource_type: request
            .match_info()
            .get("type")
            .ok_or_else(|| Error::InvalidRequest(String::from("no `type` in url")))?
            .to_string(),
        resource_tag: request
            .match_info()
            .get("tag")
            .ok_or_else(|| Error::InvalidRequest(String::from("no `tag` in url")))?
            .to_string(),
    };

    info!("Resource description: {:?}", &resource_description);

    let resource_byte = repository
        .read()
        .await
        .read_secret_resource(resource_description)
        .await
        .map_err(|e| Error::ReadSecretFailed(e.to_string()))?;

    let jwe = jwe(pubkey, resource_byte)?;

    let res = serde_json::to_string(&jwe).map_err(|e| Error::JWEFailed(e.to_string()))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(res))
}

#[cfg(feature = "as")]
async fn get_attest_claims_from_session(
    request: &HttpRequest,
    map: web::Data<SessionMap<'_>>,
) -> Result<String> {
    // check cookie
    let cookie = request
        .cookie(KBS_SESSION_ID)
        .ok_or(Error::UnAuthenticatedCookie)?;

    let session_map = map.sessions.read().await;
    let locked_session = session_map
        .get(cookie.value())
        .ok_or(Error::UnAuthenticatedCookie)?;

    let session = locked_session.lock().await;

    info!("Cookie {} request to get resource", session.id());

    if !session.is_authenticated() {
        error!("UnAuthenticated KBS cookie {}", cookie.value());
        raise_error!(Error::UnAuthenticatedCookie);
    }

    if session.is_expired() {
        error!("Expired KBS cookie {}", cookie.value());
        raise_error!(Error::ExpiredCookie);
    }

    let claims = session
        .attestation_claims()
        .ok_or(Error::AttestationClaimsGetFailed(
            "No attestation claims in the session".into(),
        ))?;

    Ok(claims)
}

async fn get_attest_claims_from_header(
    request: &HttpRequest,
    token_verifier: web::Data<Arc<RwLock<dyn AttestationTokenVerifier + Send + Sync>>>,
) -> Result<String> {
    let bearer = Authorization::<Bearer>::parse(request)
        .map_err(|e| Error::InvalidRequest(format!("parse Authorization header failed: {e}")))?
        .into_scheme();

    let token = bearer.token().to_string();

    let claims = token_verifier
        .read()
        .await
        .verify(token)
        .map_err(|e| Error::TokenParseFailed(format!("verify token failed: {e}")))?;
    Ok(claims)
}

const RSA_ALGORITHM: &str = "RSA1_5";
const AES_GCM_256_ALGORITHM: &str = "A256GCM";

pub(crate) fn jwe(tee_pub_key: TeePubKey, payload_data: Vec<u8>) -> Result<Response> {
    if tee_pub_key.alg != *RSA_ALGORITHM {
        raise_error!(Error::JWEFailed(format!(
            "algorithm is not {RSA_ALGORITHM} but {}",
            tee_pub_key.alg
        )));
    }

    let mut rng = rand::thread_rng();

    let aes_sym_key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&aes_sym_key);
    let iv = rng.gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&iv);
    let encrypted_payload_data = cipher
        .encrypt(nonce, payload_data.as_slice())
        .map_err(|e| Error::JWEFailed(format!("AES encrypt Resource payload failed: {e:?}")))?;

    let k_mod = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_mod)
        .map_err(|e| Error::JWEFailed(format!("base64 decode k_mod failed: {e:?}")))?;
    let n = BigUint::from_bytes_be(&k_mod);
    let k_exp = URL_SAFE_NO_PAD
        .decode(&tee_pub_key.k_exp)
        .map_err(|e| Error::JWEFailed(format!("base64 decode k_exp failed: {e:?}")))?;
    let e = BigUint::from_bytes_be(&k_exp);

    let rsa_pub_key = RsaPublicKey::new(n, e).map_err(|e| {
        Error::JWEFailed(format!(
            "Building RSA key from modulus and exponent failed: {e:?}"
        ))
    })?;
    let sym_key: &[u8] = aes_sym_key.as_slice();
    let wrapped_sym_key = rsa_pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, sym_key)
        .map_err(|e| Error::JWEFailed(format!("RSA encrypt sym key failed: {e:?}")))?;

    let protected_header = json!(
    {
       "alg": RSA_ALGORITHM.to_string(),
       "enc": AES_GCM_256_ALGORITHM.to_string(),
    });

    Ok(Response {
        protected: serde_json::to_string(&protected_header)
            .map_err(|e| Error::JWEFailed(format!("serde protected_header failed: {e}")))?,
        encrypted_key: URL_SAFE_NO_PAD.encode(wrapped_sym_key),
        iv: URL_SAFE_NO_PAD.encode(iv),
        ciphertext: URL_SAFE_NO_PAD.encode(encrypted_payload_data),
        tag: "".to_string(),
    })
}
