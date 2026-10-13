// Copyright (c) 2026 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::debug;

use nv_attestation_sdk::{
    EvidencePolicy, GpuEvidenceSource, GpuLocalVerifier, GpuNrasVerifier, HttpOptions, Nonce,
    NvatSdk, OcspClient, RimStore, SdkOptions, SwitchEvidenceSource, SwitchLocalVerifier,
    SwitchNrasVerifier,
};

use super::nras_response::get_jwt_payload;
use super::{check_nonce_match, Architecture, NvDeviceReportAndCert};
use crate::{TeeClass, TeeEvidenceParsedClaim};

const NVAT_CONNECTION_TIMEOUT_MS: i64 = 10_000;
const NVAT_REQUEST_TIMEOUT_MS: i64 = 60_000;
const NVAT_MAX_RETRY_COUNT: i64 = 5;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct NvidiaNvatRemoteConfig {
    #[serde(default)]
    pub nras_url: Option<String>,
    #[serde(default)]
    pub service_key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct NvidiaNvatLocalConfig {
    #[serde(default)]
    pub rim_url: Option<String>,
    #[serde(default)]
    pub rim_store_path: Option<String>,
    #[serde(default)]
    pub ocsp_url: Option<String>,
    #[serde(default)]
    pub service_key: Option<String>,
    #[serde(default = "default_true")]
    pub verify_rim_signature: bool,
    #[serde(default = "default_true")]
    pub verify_rim_cert_chain: bool,
}

fn default_true() -> bool {
    true
}

impl Default for NvidiaNvatLocalConfig {
    fn default() -> Self {
        Self {
            rim_url: None,
            rim_store_path: None,
            ocsp_url: None,
            service_key: None,
            verify_rim_signature: true,
            verify_rim_cert_chain: true,
        }
    }
}

#[derive(Clone, Debug)]
pub enum NvatMode {
    Local(NvidiaNvatLocalConfig),
    Remote(NvidiaNvatRemoteConfig),
}

fn ensure_sdk_init() -> Result<()> {
    static INIT: OnceLock<std::result::Result<(), String>> = OnceLock::new();

    INIT.get_or_init(|| {
        let opts = SdkOptions::new().map_err(|e| format!("SdkOptions::new: {e}"))?;
        let sdk = NvatSdk::init(opts).map_err(|e| format!("NvatSdk::init: {e}"))?;
        std::mem::forget(sdk);
        Ok(())
    })
    .clone()
    .map_err(|e| anyhow!("Failed to initialize NVIDIA Attestation SDK: {e}"))
}

pub(super) async fn evaluate_devices(
    devices: Vec<NvDeviceReportAndCert>,
    expected_nonce: Vec<u8>,
    mode: NvatMode,
) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
    tokio::task::spawn_blocking(move || evaluate_devices_blocking(devices, expected_nonce, mode))
        .await
        .context("NVAT verification task failed to join")?
}

fn evaluate_devices_blocking(
    devices: Vec<NvDeviceReportAndCert>,
    expected_nonce: Vec<u8>,
    mode: NvatMode,
) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
    ensure_sdk_init()?;

    let nonce = Nonce::from_hex(&hex::encode(&expected_nonce)).context("build NVAT nonce")?;

    let mut gpu_devices: Vec<NvDeviceReportAndCert> = Vec::new();
    let mut switch_devices: Vec<NvDeviceReportAndCert> = Vec::new();
    for device in devices {
        match device.arch {
            Architecture::Hopper | Architecture::Blackwell => gpu_devices.push(device),
            Architecture::LS10 => switch_devices.push(device),
        }
    }

    let mut all_claims: Vec<(TeeEvidenceParsedClaim, TeeClass)> = Vec::new();

    if !gpu_devices.is_empty() {
        let evidence_json = devices_to_nvat_json(&gpu_devices, &expected_nonce)?;
        let source = GpuEvidenceSource::from_json_string(&evidence_json)
            .context("create GPU evidence source from JSON")?;
        let evidence = source.collect(&nonce).context("collect GPU evidence")?;

        let result = match &mode {
            NvatMode::Local(config) => {
                let (rim_store, ocsp_client) = build_rim_ocsp(config)?;
                let policy = build_local_policy(config)?;
                let verifier = GpuLocalVerifier::new(&rim_store, &ocsp_client)
                    .context("create GPU local verifier")?;
                verifier
                    .verify(&evidence, &policy)
                    .context("verify GPU evidence")?
            }
            NvatMode::Remote(config) => {
                let http_opts = build_http_options()?;
                let verifier = GpuNrasVerifier::new(
                    config.nras_url.as_deref(),
                    config.service_key.as_deref(),
                    Some(&http_opts),
                )
                .context("create GPU NRAS verifier")?;
                let policy = EvidencePolicy::default_policy().context("create default policy")?;
                verifier
                    .verify(&evidence, &policy)
                    .context("verify GPU evidence")?
            }
        };

        let eat_json = result.eat_json().context("read NVAT detached EAT")?;
        all_claims.extend(claims_from_eat_json(&eat_json, "gpu")?);
    }

    if !switch_devices.is_empty() {
        let evidence_json = devices_to_nvat_json(&switch_devices, &expected_nonce)?;
        let source = SwitchEvidenceSource::from_json_string(&evidence_json)
            .context("create switch evidence source from JSON")?;
        let evidence = source.collect(&nonce).context("collect switch evidence")?;

        let result = match &mode {
            NvatMode::Local(config) => {
                let (rim_store, ocsp_client) = build_rim_ocsp(config)?;
                let policy = build_local_policy(config)?;
                let verifier = SwitchLocalVerifier::new(&rim_store, &ocsp_client)
                    .context("create switch local verifier")?;
                verifier
                    .verify(&evidence, &policy)
                    .context("verify switch evidence")?
            }
            NvatMode::Remote(config) => {
                let http_opts = build_http_options()?;
                let verifier = SwitchNrasVerifier::new(
                    config.nras_url.as_deref(),
                    config.service_key.as_deref(),
                    Some(&http_opts),
                )
                .context("create switch NRAS verifier")?;
                let policy = EvidencePolicy::default_policy().context("create default policy")?;
                verifier
                    .verify(&evidence, &policy)
                    .context("verify switch evidence")?
            }
        };

        let eat_json = result.eat_json().context("read NVAT detached EAT")?;
        all_claims.extend(claims_from_eat_json(&eat_json, "switch")?);
    }

    Ok(all_claims)
}

fn devices_to_nvat_json(devices: &[NvDeviceReportAndCert], nonce: &[u8]) -> Result<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let nonce_hex = hex::encode(nonce);

    let array: Vec<Value> = devices
        .iter()
        .map(|device| {
            let evidence_b64 = match hex::decode(&device.evidence) {
                Ok(bytes) => b64.encode(bytes),
                Err(_) => device.evidence.clone(),
            };

            json!({
                "arch": device.arch.to_string().to_uppercase(),
                "nonce": nonce_hex,
                "evidence": evidence_b64,
                "certificate": device.certificate,
            })
        })
        .collect();

    serde_json::to_string(&array).context("serialize evidence for NVAT")
}

fn build_rim_ocsp(config: &NvidiaNvatLocalConfig) -> Result<(RimStore, OcspClient)> {
    let http_opts = build_http_options()?;

    let rim_store = if let Some(path) = &config.rim_store_path {
        RimStore::create_filesystem(path).context("create filesystem RIM store")?
    } else {
        RimStore::create_remote(
            config.rim_url.as_deref(),
            config.service_key.as_deref(),
            Some(&http_opts),
        )
        .context("create remote RIM store")?
    };

    let ocsp_client = OcspClient::create_default(
        config.ocsp_url.as_deref(),
        config.service_key.as_deref(),
        Some(&http_opts),
    )
    .context("create OCSP client")?;

    Ok((rim_store, ocsp_client))
}

fn build_local_policy(config: &NvidiaNvatLocalConfig) -> Result<EvidencePolicy> {
    EvidencePolicy::builder()
        .verify_rim_signature(config.verify_rim_signature)
        .verify_rim_cert_chain(config.verify_rim_cert_chain)
        .build()
        .context("build evidence policy")
}

fn build_http_options() -> Result<HttpOptions> {
    HttpOptions::builder()
        .max_retry_count(NVAT_MAX_RETRY_COUNT)
        .connection_timeout_ms(NVAT_CONNECTION_TIMEOUT_MS)
        .request_timeout_ms(NVAT_REQUEST_TIMEOUT_MS)
        .build()
        .context("build HTTP options")
}

#[derive(Debug, Deserialize)]
struct DetachedEatBundle(Vec<String>, HashMap<String, String>);

fn claims_from_eat_json(
    eat_json: &str,
    tee_class: &str,
) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
    let bundle: DetachedEatBundle = serde_json::from_str(eat_json)
        .context("parse NVAT detached EAT bundle (expected NRAS-style layout)")?;

    if bundle.0.len() != 2 {
        anyhow::bail!("Unexpected detached EAT overall-token format");
    }
    let overall_jwt = bundle.0[1].clone();
    let overall_payload = get_jwt_payload(overall_jwt)?;
    let overall_result = overall_payload
        .pointer("/x-nvidia-overall-att-result")
        .cloned();

    let mut claims = Vec::with_capacity(bundle.1.len());
    for detached_jwt in bundle.1.into_values() {
        let mut device_claims = get_jwt_payload(detached_jwt)?;

        if let Some(overall) = &overall_result {
            if let Some(map) = device_claims.as_object_mut() {
                map.insert("x-nvidia-overall-att-result".to_string(), overall.clone());
            }
        }

        debug!("NRAS {tee_class} EAT:\n{device_claims:#}");
        check_nonce_match(&device_claims, tee_class)?;

        claims.push((device_claims, tee_class.to_string()));
    }

    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvidia::{NvidiaVerifierConfig, NvidiaVerifierType};

    fn fake_jwt(payload: &Value) -> String {
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
        let header = b64.encode(br#"{"alg":"none"}"#);
        let body = b64.encode(serde_json::to_vec(payload).unwrap());
        format!("{header}.{body}.sig")
    }

    #[test]
    fn nvremote_config_deserializes() {
        let json = serde_json::json!({
            "type": "NvRemote",
            "nras_url": "https://nras.example.com",
            "service_key": "abc123"
        });
        let config: NvidiaVerifierConfig = serde_json::from_value(json).unwrap();
        let NvidiaVerifierType::NvRemote(remote) = config.verifier else {
            panic!("expected NvRemote variant");
        };
        assert_eq!(remote.nras_url.as_deref(), Some("https://nras.example.com"));
        assert_eq!(remote.service_key.as_deref(), Some("abc123"));
    }

    #[test]
    fn nvlocal_config_defaults_verification_flags_to_true() {
        let json = serde_json::json!({
            "type": "NvLocal",
            "rim_url": "https://rim.example.com"
        });
        let config: NvidiaVerifierConfig = serde_json::from_value(json).unwrap();
        let NvidiaVerifierType::NvLocal(local) = config.verifier else {
            panic!("expected NvLocal variant");
        };
        assert_eq!(local.rim_url.as_deref(), Some("https://rim.example.com"));
        assert_eq!(local.rim_store_path, None);
        assert!(local.verify_rim_signature);
        assert!(local.verify_rim_cert_chain);
    }

    #[test]
    fn nvlocal_config_alias_and_flag_override() {
        let json = serde_json::json!({
            "type": "nvlocal",
            "rim_store_path": "/var/lib/nvat/rims",
            "verify_rim_signature": false
        });
        let config: NvidiaVerifierConfig = serde_json::from_value(json).unwrap();
        let NvidiaVerifierType::NvLocal(local) = config.verifier else {
            panic!("expected NvLocal variant");
        };
        assert_eq!(local.rim_store_path.as_deref(), Some("/var/lib/nvat/rims"));
        assert!(!local.verify_rim_signature);
        assert!(local.verify_rim_cert_chain);
    }

    #[test]
    fn devices_to_nvat_json_uppercases_arch_and_normalizes_evidence() {
        let hex_evidence = hex::encode(b"raw-report-bytes");
        let devices = vec![
            NvDeviceReportAndCert {
                arch: Architecture::Hopper,
                uuid: "gpu-uuid".to_string(),
                evidence: hex_evidence.clone(),
                certificate: "cert-b64".to_string(),
            },
            NvDeviceReportAndCert {
                arch: Architecture::LS10,
                uuid: "switch-uuid".to_string(),
                evidence: "YWxyZWFkeS1iNjQ=".to_string(),
                certificate: "cert2-b64".to_string(),
            },
        ];

        let nonce = b"0123456789abcdef0123456789abcdef";
        let json = devices_to_nvat_json(&devices, nonce).unwrap();
        let parsed: Vec<Value> = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed[0]["arch"], "HOPPER");
        assert_eq!(parsed[0]["nonce"], hex::encode(nonce));
        assert_eq!(parsed[1]["nonce"], hex::encode(nonce));
        let b64 = base64::engine::general_purpose::STANDARD;
        assert_eq!(
            parsed[0]["evidence"],
            Value::String(b64.encode(b"raw-report-bytes"))
        );
        assert_eq!(parsed[1]["arch"], "LS10");
        assert_eq!(parsed[1]["evidence"], "YWxyZWFkeS1iNjQ=");
    }

    #[test]
    fn claims_from_eat_json_extracts_and_attaches_overall_result() {
        let overall = fake_jwt(&serde_json::json!({
            "x-nvidia-overall-att-result": true
        }));
        let device = fake_jwt(&serde_json::json!({
            "x-nvidia-gpu-attestation-report-nonce-match": true,
            "x-nvidia-gpu-arch-check": true
        }));
        let eat = serde_json::json!([["JWT", overall], {"GPU-0": device}]).to_string();

        let claims = claims_from_eat_json(&eat, "gpu").unwrap();
        assert_eq!(claims.len(), 1);
        let (value, class) = &claims[0];
        assert_eq!(class, "gpu");
        assert_eq!(value["x-nvidia-overall-att-result"], true);
        assert_eq!(value["x-nvidia-gpu-arch-check"], true);
    }

    #[test]
    fn claims_from_eat_json_rejects_nonce_mismatch() {
        let overall = fake_jwt(&serde_json::json!({
            "x-nvidia-overall-att-result": true
        }));
        let device = fake_jwt(&serde_json::json!({
            "x-nvidia-gpu-attestation-report-nonce-match": false
        }));
        let eat = serde_json::json!([["JWT", overall], {"GPU-0": device}]).to_string();

        assert!(claims_from_eat_json(&eat, "gpu").is_err());
    }
}
