// Copyright (c) 2026 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::{debug, warn};

use nv_attestation_sdk::{
    EvidencePolicy, GpuEvidenceSource, GpuLocalVerifier, GpuNrasVerifier, HttpOptions, Nonce,
    NvatSdk, OcspClient, RimStore, SdkOptions, SwitchEvidenceSource, SwitchLocalVerifier,
    SwitchNrasVerifier,
};

use super::eat::DetachedEat;
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

        // Usually the collect method gathers evidence from the devices, thus it
        // takes a nonce. In this case, the source is preset with JSON evidence
        // so this is redundant.
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

        if !result.is_success() {
            warn!("NVAT gpu verdict negative: {}", result.result_message());
        }
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

        if !result.is_success() {
            warn!("NVAT switch verdict negative: {}", result.result_message());
        }
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

    let rim_store = match &config.rim_store_path {
        Some(path) => RimStore::create_filesystem(path).context("create filesystem RIM store")?,
        None => RimStore::create_remote(
            config.rim_url.as_deref(),
            config.service_key.as_deref(),
            Some(&http_opts),
        )
        .context("create remote RIM store")?,
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

fn claims_from_eat_json(
    eat_json: &str,
    tee_class: &str,
) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
    let eat = DetachedEat::from_str(eat_json).context("parse NVAT detached EAT")?;

    eat.claims()?
        .into_iter()
        .map(|claims| {
            debug!("NRAS {tee_class} EAT:\n{claims:#}");
            check_nonce_match(&claims, tee_class)?;
            Ok((claims, tee_class.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nvidia::{NvidiaVerifierConfig, NvidiaVerifierType};
    use rstest::rstest;

    fn fake_jwt(payload: &Value) -> String {
        let b64 = base64::engine::general_purpose::STANDARD_NO_PAD;
        let header = b64.encode(br#"{"alg":"none"}"#);
        let body = b64.encode(serde_json::to_vec(payload).unwrap());
        format!("{header}.{body}.sig")
    }

    #[rstest]
    #[case::all_fields(
        json!({
            "type": "NvRemote",
            "nras_url": "https://nras.example.com",
            "service_key": "abc123"
        }),
        Some("https://nras.example.com"),
        Some("abc123")
    )]
    #[case::defaults(json!({"type": "NvRemote"}), None, None)]
    fn nvremote_config_deserializes(
        #[case] input: Value,
        #[case] nras_url: Option<&str>,
        #[case] service_key: Option<&str>,
    ) {
        let config: NvidiaVerifierConfig = serde_json::from_value(input).unwrap();
        let NvidiaVerifierType::NvRemote(remote) = config.verifier else {
            panic!("expected NvRemote variant");
        };
        assert_eq!(remote.nras_url.as_deref(), nras_url);
        assert_eq!(remote.service_key.as_deref(), service_key);
    }

    #[rstest]
    #[case::defaults_verification_flags_to_true(
        json!({
            "type": "NvLocal",
            "rim_url": "https://rim.example.com"
        }),
        Some("https://rim.example.com"),
        None,
        true,
        true
    )]
    #[case::alias_and_flag_override(
        json!({
            "type": "nvlocal",
            "rim_store_path": "/var/lib/nvat/rims",
            "verify_rim_signature": false
        }),
        None,
        Some("/var/lib/nvat/rims"),
        false,
        true
    )]
    fn nvlocal_config_deserializes(
        #[case] input: Value,
        #[case] rim_url: Option<&str>,
        #[case] rim_store_path: Option<&str>,
        #[case] verify_rim_signature: bool,
        #[case] verify_rim_cert_chain: bool,
    ) {
        let config: NvidiaVerifierConfig = serde_json::from_value(input).unwrap();
        let NvidiaVerifierType::NvLocal(local) = config.verifier else {
            panic!("expected NvLocal variant");
        };
        assert_eq!(local.rim_url.as_deref(), rim_url);
        assert_eq!(local.rim_store_path.as_deref(), rim_store_path);
        assert_eq!(local.verify_rim_signature, verify_rim_signature);
        assert_eq!(local.verify_rim_cert_chain, verify_rim_cert_chain);
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

    #[rstest]
    #[case::nonce_match(true)]
    #[case::nonce_mismatch(false)]
    fn claims_from_eat_json_checks_nonce(#[case] nonce_match: bool) {
        let overall = fake_jwt(&json!({
            "x-nvidia-overall-att-result": true
        }));
        let device = fake_jwt(&json!({
            "x-nvidia-gpu-attestation-report-nonce-match": nonce_match,
            "x-nvidia-gpu-arch-check": true
        }));
        let eat = json!([["JWT", overall], {"GPU-0": device}]).to_string();

        let claims = claims_from_eat_json(&eat, "gpu");
        if !nonce_match {
            assert!(claims.is_err());
            return;
        }

        let claims = claims.unwrap();
        assert_eq!(claims.len(), 1);
        let (value, class) = &claims[0];
        assert_eq!(class, "gpu");
        assert_eq!(value["x-nvidia-overall-att-result"], true);
        assert_eq!(value["x-nvidia-gpu-arch-check"], true);
    }
}
