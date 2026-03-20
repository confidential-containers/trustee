// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS client SDK.

use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use kbs_protocol::evidence_provider::NativeEvidenceProvider;
use kbs_protocol::token_provider::TestTokenProvider;
use kbs_protocol::KbsClientBuilder;
use kbs_protocol::KbsClientCapabilities;
use serde::Serialize;
use serde_json::json;
use tracing::warn;

const KBS_URL_PREFIX: &str = "kbs/v0";

/// Attestation and get a result token signed by attestation service
/// Input parameters:
/// - url: KBS server root URL.
/// - [tee_pubkey_pem]: Public key (PEM format) of the RSA key pair generated in TEE.
///   This public key will be contained in attestation results token.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
/// - init_data: Plaintext init-data; should correspond to init-data measured at boot time.
pub async fn attestation(
    url: &str,
    tee_key_pem: Option<String>,
    kbs_root_certs_pem: Vec<String>,
    init_data: Option<String>,
) -> Result<String> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, url);

    if let Some(key) = tee_key_pem {
        client_builder = client_builder.set_tee_key(&key)
    }

    for cert in kbs_root_certs_pem {
        client_builder = client_builder.add_kbs_cert(&cert)
    }

    if let Some(init_data) = init_data {
        client_builder = client_builder.add_initdata(init_data);
    }

    let mut client = client_builder.build()?;

    let (token, _) = client.get_token().await?;

    Ok(token.content)
}

/// Get secret resources with attestation results token
/// Input parameters:
/// - url: KBS server root URL.
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - tee_key_pem: TEE private key file path (PEM format). This key must consistent with the public key in `token` claims.
/// - token: Attestation Results Token file path.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn get_resource_with_token(
    url: &str,
    path: &str,
    tee_key_pem: String,
    token: String,
    kbs_root_certs_pem: Vec<String>,
) -> Result<Vec<u8>> {
    let token_provider = Box::<TestTokenProvider>::default();
    let mut client_builder =
        KbsClientBuilder::with_token_provider(token_provider, url).set_token(&token);
    client_builder = client_builder.set_tee_key(&tee_key_pem);

    for cert in kbs_root_certs_pem {
        client_builder = client_builder.add_kbs_cert(&cert)
    }
    let mut client = client_builder.build()?;

    let resource_kbs_uri = format!("kbs:///{path}");
    let resource_bytes = client
        .get_resource(serde_json::from_str(&format!("\"{resource_kbs_uri}\""))?)
        .await?;
    Ok(resource_bytes)
}

/// Get secret resources with attestation
/// Input parameters:
/// - url: KBS server root URL.
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - [tee_pubkey_pem]: Public key (PEM format) of the RSA key pair generated in TEE.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
/// - init_data: Plaintext init-data; should correspond to init-data measured at boot time.
pub async fn get_resource_with_attestation(
    url: &str,
    path: &str,
    tee_key_pem: Option<String>,
    kbs_root_certs_pem: Vec<String>,
    init_data: Option<String>,
) -> Result<Vec<u8>> {
    let evidence_provider = Box::new(NativeEvidenceProvider::new()?);
    let mut client_builder = KbsClientBuilder::with_evidence_provider(evidence_provider, url);
    if let Some(key) = tee_key_pem {
        client_builder = client_builder.set_tee_key(&key);
    }

    for cert in kbs_root_certs_pem {
        client_builder = client_builder.add_kbs_cert(&cert)
    }

    if let Some(init_data) = init_data {
        client_builder = client_builder.add_initdata(init_data);
    }

    let mut client = client_builder.build()?;

    let resource_kbs_uri = format!("kbs:///{path}");
    let resource_bytes = client
        .get_resource(serde_json::from_str(&format!("\"{resource_kbs_uri}\""))?)
        .await?;
    Ok(resource_bytes)
}

#[derive(Serialize)]
pub struct SetPolicyInput {
    pub r#type: String,
    pub policy_id: String,
    pub policy: String,
}

/// Set attestation policy
/// Input parameters:
/// - url: KBS server root URL.
/// - admin_token: Optional admin bearer token. If None, request is anonymous.
/// - policy_bytes: Policy file content in `Vec<u8>`.
/// - [policy_type]: Policy type. Default value is "rego".
/// - [policy_id]: Policy ID. Default value is "default_cpu".
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_attestation_policy(
    url: &str,
    admin_token: Option<String>,
    policy_bytes: Vec<u8>,
    policy_type: Option<String>,
    policy_id: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let http_client = build_http_client(kbs_root_certs_pem)?;

    let set_policy_url = format!("{}/{KBS_URL_PREFIX}/attestation-policy", url);
    let policy_id = match policy_id {
        Some(policy_id) => policy_id,
        None => {
            warn!("no policy_id set; using default_cpu");
            "default_cpu".to_string()
        }
    };
    let post_input = SetPolicyInput {
        r#type: policy_type.unwrap_or("rego".to_string()),
        policy_id,
        policy: URL_SAFE_NO_PAD.encode(policy_bytes.clone()),
    };

    let mut req = http_client
        .post(set_policy_url)
        .header("Content-Type", "application/json")
        .json::<SetPolicyInput>(&post_input);
    if let Some(token) = admin_token {
        req = req.bearer_auth(token);
    } else {
        warn!("No admin token provided; sending anonymous request");
    }
    let res = req.send().await?;

    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

#[derive(Clone, Serialize)]
struct ResourcePolicyData {
    pub policy: String,
}

/// Set resource policy
/// Input parameters:
/// - url: KBS server root URL.
/// - admin_token: Optional admin bearer token. If None, request is anonymous.
/// - policy_bytes: Policy file content in `Vec<u8>`.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_resource_policy(
    url: &str,
    admin_token: Option<String>,
    policy_bytes: Vec<u8>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let http_client = build_http_client(kbs_root_certs_pem)?;

    let set_policy_url = format!("{}/{KBS_URL_PREFIX}/resource-policy", url);
    let post_input = ResourcePolicyData {
        policy: URL_SAFE_NO_PAD.encode(policy_bytes.clone()),
    };

    let mut req = http_client
        .post(set_policy_url)
        .header("Content-Type", "application/json")
        .json::<ResourcePolicyData>(&post_input);
    if let Some(token) = admin_token {
        req = req.bearer_auth(token);
    } else {
        warn!("No admin token provided; sending anonymous request");
    }
    let res = req.send().await?;

    if res.status() != reqwest::StatusCode::OK {
        bail!("Request Failed, Response: {:?}", res.text().await?);
    }
    Ok(())
}

/// Set secret resource to KBS.
/// Input parameters:
/// - url: KBS server root URL.
/// - admin_token: Optional admin bearer token. If None, request is anonymous.
/// - resource_bytes: Resource data in `Vec<u8>`
/// - path: Resource path, format must be `<top>/<middle>/<tail>`, e.g. `alice/key/example`.
/// - kbs_root_certs_pem: Custom HTTPS root certificate of KBS server. It can be left blank.
pub async fn set_resource(
    url: &str,
    admin_token: Option<String>,
    resource_bytes: Vec<u8>,
    path: &str,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let http_client = build_http_client(kbs_root_certs_pem)?;

    let resource_url = format!("{}/{KBS_URL_PREFIX}/resource/{}", url, path);
    let mut req = http_client
        .post(resource_url)
        .header("Content-Type", "application/octet-stream")
        .body(resource_bytes.clone());
    if let Some(token) = admin_token {
        req = req.bearer_auth(token);
    } else {
        warn!("No admin token provided; sending anonymous request");
    }
    let res = req.send().await?;
    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

/// Set a reference value in the RVPS at <url>
/// RVPS must be configured with the non-secure sample extractor
/// The RVPS-tool should be used in production environments
pub async fn set_sample_rv(
    url: String,
    key: String,
    value: serde_json::Value,
    admin_token: Option<String>,
    kbs_root_certs_pem: Vec<String>,
) -> Result<()> {
    let http_client = build_http_client(kbs_root_certs_pem)?;

    let reference_value_url = format!("{}/{KBS_URL_PREFIX}/reference-value", url);

    let provenance = json!({key: value}).to_string();
    let provenance = STANDARD.encode(provenance);

    let message = json!({
        "version": "0.1.0",
        "type": "sample",
        "payload": provenance
    });

    let mut req = http_client
        .post(reference_value_url)
        .header("Content-Type", "application/json")
        .body(message.to_string());
    if let Some(token) = admin_token {
        req = req.bearer_auth(token);
    } else {
        warn!("No admin token provided; sending anonymous request");
    }
    let res = req.send().await?;

    match res.status() {
        reqwest::StatusCode::OK => Ok(()),
        _ => {
            bail!("Request Failed, Response: {:?}", res.text().await?)
        }
    }
}

pub async fn get_rv(
    url: String,
    admin_token: Option<String>,
    kbs_root_certs_pem: Vec<String>,
    reference_value_id: String,
) -> Result<String> {
    let http_client = build_http_client(kbs_root_certs_pem)?;

    let reference_value_url = format!(
        "{}/{KBS_URL_PREFIX}/reference-value/{reference_value_id}",
        url
    );

    let mut req = http_client
        .get(reference_value_url)
        .header("Content-Type", "application/json");
    if let Some(token) = admin_token {
        req = req.bearer_auth(token);
    } else {
        warn!("No admin token provided; sending anonymous request");
    }
    let res = req.send().await?;

    match res.status() {
        reqwest::StatusCode::OK => Ok(res.text().await?),
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
