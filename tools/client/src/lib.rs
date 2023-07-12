// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS client SDK.

use anyhow::{anyhow, bail, Result};
use as_types::SetPolicyInput;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair, EdDSAKeyPairLike};
use kbs_protocol::{KbsProtocolWrapper, KbsRequest};

const KBS_URL_PREFIX: &str = "kbs/v0";

/// Attestation and get a result token signed by attestation service
/// Input parameters:
/// - url: KBS server root URL.
/// - [tee_pubkey_pem]: Public key (PEM format) of the RSA key pair generated in TEE.
///     This public key will be contained in attestation results token.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn attestation(
    url: &str,
    tee_pubkey_pem: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<String> {
    let mut kbs_protocol_wrapper = KbsProtocolWrapper::new(kbs_root_certs_pem)?;
    let token = kbs_protocol_wrapper
        .attest(url.to_string(), tee_pubkey_pem)
        .await?;
    Ok(token)
}

/// Get secret resources with attestation
/// Input parameters:
/// - url: KBS server root URL.
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn get_resource(
    url: &str,
    path: &str,
    kbs_root_certs_pem: Vec<String>,
) -> Result<Vec<u8>> {
    let mut kbs_protocol_wrapper = KbsProtocolWrapper::new(kbs_root_certs_pem)?;
    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", url, path);
    let resource_bytes = kbs_protocol_wrapper.http_get(resource_url).await?;
    Ok(resource_bytes)
}

/// Set attestation policy
/// Input parameters:
/// - url: KBS server root URL.
/// - auth_key: KBS owner's authenticate private key (PEM string).
/// - policy_bytes: Policy file content in `Vec<u8>`.
/// - [policy_type]: Policy type. Default value is "rego".
/// - [policy_id]: Policy ID. Default value is "default".
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_attestation_policy(
    url: &str,
    auth_key: String,
    policy_bytes: Vec<u8>,
    policy_type: Option<String>,
    policy_id: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let auth_private_key = Ed25519KeyPair::from_pem(&auth_key)?;
    let claims = Claims::create(Duration::from_hours(2));
    let token = auth_private_key.sign(claims)?;

    let http_client = build_http_client(kbs_root_certs_pem)?;

    let set_policy_url = format!("{}/{KBS_URL_PREFIX}/attestation-policy", url);
    let post_input = SetPolicyInput {
        r#type: policy_type.unwrap_or("rego".to_string()),
        policy_id: policy_id.unwrap_or("default".to_string()),
        policy: base64::encode(policy_bytes.clone()),
    };

    let res = http_client
        .post(set_policy_url)
        .header("Content-Type", "application/json")
        .bearer_auth(token.clone())
        .json::<SetPolicyInput>(&post_input)
        .send()
        .await?;

    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

/// Set secret resource to KBS.
/// Input parameters:
/// - url: KBS server root URL.
/// - auth_key: KBS owner's authenticate private key (PEM string).
/// - resource_bytes: Resource data in `Vec<u8>`
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_resource(
    url: &str,
    auth_key: String,
    resource_bytes: Vec<u8>,
    path: &str,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let auth_private_key = Ed25519KeyPair::from_pem(&auth_key)?;
    let claims = Claims::create(Duration::from_hours(2));
    let token = auth_private_key.sign(claims)?;

    let http_client = build_http_client(kbs_root_certs_pem)?;

    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", url, path);
    let res = http_client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .bearer_auth(token)
        .body(resource_bytes.clone())
        .send()
        .await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

fn build_http_client(kbs_root_certs_pem: Vec<String>) -> Result<reqwest::Client> {
    let mut client_builder =
        reqwest::Client::builder().user_agent(format!("kbs-client/{}", env!("CARGO_PKG_VERSION")));

    for custom_root_cert in kbs_root_certs_pem.iter() {
        let cert = reqwest::Certificate::from_pem(custom_root_cert.as_bytes())?;
        client_builder = client_builder.add_root_certificate(cert);
    }

    client_builder
        .build()
        .map_err(|e| anyhow!("Build KBS http client failed: {:?}", e))
}
