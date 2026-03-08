// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod cert_chain;
pub mod nras_jwks;
pub mod nras_response;
pub mod report;
pub mod spdm_request;
pub mod spdm_response;

use anyhow::{bail, Result};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::result::Result::Ok;
use std::str::FromStr;
use strum::{Display, EnumString};
use tracing::{instrument, trace};

use super::*;
use crate::nvidia::nras_jwks::NrasJwks;
use crate::nvidia::nras_response::NrasResponse;
use crate::nvidia::report::NvidiaAttestationReport;

const HOPPER_SIGNATURE_LENGTH: usize = 96;

/// Only SPDM Version 1.1 is supported
pub const SPDM_VERSION_SUPPORTED: u8 = 0x11;
pub const SPDM_NONCE_SIZE: usize = 32;

// Only measurements encoded in the DMTF_MEASUREMENT layout are supported
pub const DMTF_MEASUREMENT_SPECIFICATION_VALUE: u8 = 1;

/// Accessing NRAS requires entering into a licensing agreement with NVIDIA.
/// Using Trustee with the NRAS remote verifier assumes that you have done this.
pub const NRAS_URL: &str = "https://nras.attestation.nvidia.com/v4/attest";

#[derive(Default, Debug)]
pub struct Nvidia {
    verifier_type: NvidiaVerifierType,
    nras_jwks: Option<NrasJwks>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct NvidiaVerifierConfig {
    #[serde(flatten)]
    verifier: NvidiaVerifierType,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum NvidiaVerifierType {
    #[default]
    #[serde(alias = "local")]
    Local,
    #[serde(alias = "remote")]
    Remote(NvidiaRemoteVerifierConfig),
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct NvidiaRemoteVerifierConfig {
    verifier_url: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct NvDeviceEvidence {
    device_evidence_list: Vec<NvDeviceReportAndCert>,
}

// NVML Wrapper does not know about switches,
// so create our own enum for the device architecture.
#[derive(Debug, Deserialize, Display, EnumString, PartialEq, Serialize)]
#[strum(ascii_case_insensitive)]
enum Architecture {
    #[serde(alias = "BLACKWELL")]
    Blackwell,
    #[serde(alias = "HOPPER")]
    Hopper,
    LS10,
}

#[derive(Debug, Deserialize, Serialize)]
struct NvDeviceReportAndCert {
    arch: Architecture,
    #[serde(default = "default_uuid")]
    uuid: String,
    evidence: String,
    certificate: String,
}

/// UUID isn't used for attestation and isn't reported by the NVAT
/// bindings. To maintain backwards comptability, keep UUID in the
/// struct, but don't require it.
fn default_uuid() -> String {
    "unknown".to_string()
}

#[derive(Default, Debug, Serialize)]
pub struct NvDeviceReportAndCertClaim {
    arch: String,
    uuid: String,
    measurements: HashMap<u8, String>,
    config: HashMap<String, Value>,
}

impl NvDeviceReportAndCertClaim {
    fn new(
        device_arch: &Architecture,
        device_uuid: &str,
        attestation_report: &NvidiaAttestationReport,
    ) -> Self {
        let mut measurements: HashMap<u8, String> =
            HashMap::with_capacity(attestation_report.response.number_of_blocks);
        for block in &attestation_report.response.measurement_record {
            measurements.insert(block.index, hex::encode(&block.measurement.value));
        }

        Self {
            arch: device_arch.to_string(),
            uuid: device_uuid.to_string(),
            measurements,
            config: attestation_report.response.opaque_data.clone(),
        }
    }
}

/// Check if a set of device claims constitutes a PPCIE configuration.
/// If so, return claims describing the PPCIE topology.
fn validate_ppcie(
    all_devices_claims: Vec<(TeeEvidenceParsedClaim, TeeClass)>,
) -> Result<TeeEvidenceParsedClaim> {
    if all_devices_claims.len() != 12 {
        bail!("PPCIE requires 12 devices.");
    }

    let mut gpu_pdis: HashSet<String> = HashSet::new();
    let mut switch_pdis: HashSet<String> = HashSet::new();

    for (claims, device_class) in all_devices_claims {
        if device_class == "gpu" {
            let gpu_switch_pdis = claims
                .pointer("/x-nvidia-gpu-switch-pdis")
                .ok_or(anyhow!("gpu must specify switch PDIs"))?
                .as_array()
                .ok_or(anyhow!("gpu must specify switch PDIs as array"))?
                .iter();

            let mut switch_count = 0;
            for switch_pdi in gpu_switch_pdis {
                let switch_pdi = switch_pdi
                    .as_str()
                    .ok_or(anyhow!("switch PDI must be string"))?;
                if switch_pdi.contains("0000000000000000") {
                    continue;
                }

                switch_pdis.insert(switch_pdi.to_string());
                switch_count += 1;
            }
            if switch_count != 4 {
                bail!("Each GPU must be connectd to 4 switches");
            }
        } else if device_class == "switch" {
            let switch_pdi = claims
                .pointer("/x-nvidia-switch-pdi")
                .ok_or(anyhow!("switch must specify it's own PDI"))?
                .as_str()
                .ok_or(anyhow!("switch must specify it's own PDI as string"))?;

            switch_pdis.insert(switch_pdi.to_string());

            let switch_gpu_pdis = claims
                .pointer("/x-nvidia-switch-gpu-pdis")
                .ok_or(anyhow!("switch must specify GPU PDIs"))?
                .as_array()
                .ok_or(anyhow!("switch must specify it's GPU PDIs as array"))?
                .iter();
            if switch_gpu_pdis.len() != 8 {
                bail!("Each switch must be connectd to 8 GPUs");
            }

            for gpu_pdi in switch_gpu_pdis {
                gpu_pdis.insert(
                    gpu_pdi
                        .as_str()
                        .ok_or(anyhow!("GPU PDI must be string"))?
                        .to_string(),
                );
            }
        }
    }

    if gpu_pdis.len() != 8 {
        bail!("Topology must contain 8 GPUs");
    }
    if switch_pdis.len() != 4 {
        bail!("Topology must contain 4 switches");
    }

    let claims = json!({"switch_count":4, "gpu_count":8 });

    Ok(claims)
}

impl Nvidia {
    pub async fn new(config: Option<NvidiaVerifierConfig>) -> Result<Self> {
        let verifier_type = config
            .map(|c| c.verifier)
            .unwrap_or(NvidiaVerifierType::Local);

        let nras_jwks = match verifier_type {
            NvidiaVerifierType::Remote(_) => Some(NrasJwks::new().await?),
            _ => None,
        };

        Ok(Nvidia {
            verifier_type,
            nras_jwks,
        })
    }

    /// Evaluate an NVIDIA device using NRAS
    async fn evaluate_device_nras(
        &self,
        device: NvDeviceReportAndCert,
        expected_nonce_vec: Vec<u8>,
        config: &NvidiaRemoteVerifierConfig,
    ) -> Result<(TeeEvidenceParsedClaim, String)> {
        let b64_engine = base64::engine::general_purpose::STANDARD;

        let (tee_class, endpoint) = match device.arch {
            Architecture::Blackwell => ("gpu", "gpu"),
            Architecture::Hopper => ("gpu", "gpu"),
            Architecture::LS10 => ("switch", "switch"),
        };

        // Try hex::decode() to see if someone uses the original encoding still.
        // An Err Result suggests the evidence is already base64 encoded and can be used as is.
        let evidence_b64 = match hex::decode(&device.evidence) {
            Ok(evidence) => b64_engine.encode(evidence),
            Err(e) => {
                debug!("Device evidence is not hex encoded (decoding failed with: {e}). Using it as is.");
                device.evidence
            }
        };

        // We could batch devices with the same architecture together into one request,
        // but for now, check one device at a time.
        let request_url = format!(
            "{}/{}",
            config.verifier_url.clone().unwrap_or(NRAS_URL.to_string()),
            endpoint
        );

        let request_json = json!({
            "nonce": hex::encode(expected_nonce_vec),
            "arch": device.arch.to_string().to_uppercase(),
            "evidence_list": [
                {
                    "evidence": evidence_b64,
                    "certificate": device.certificate,
                }
            ],
            "claims_version": "3.0"
        });

        // We can reuse this client for multiple requests, but for now create a new one.
        let client = reqwest::Client::new();
        let res = client.post(request_url).json(&request_json).send().await?;

        if !res.status().is_success() {
            bail!(
                "Request Failed with {}. Details: {}",
                res.status(),
                res.text().await?
            )
        };

        let response = NrasResponse::from_str(&res.text().await?)?;
        if let Some(jwks) = &self.nras_jwks {
            response.validate(jwks)?;
        } else {
            bail!("JWKs not available.");
        }

        let claims = response.claims()?;

        // Check that the nonce matches the expected report data.
        // Consider moving this logic into the NrasResponse struct.
        let nonce_ok = claims
            .pointer(&format!(
                "/x-nvidia-{endpoint}-attestation-report-nonce-match"
            ))
            .ok_or_else(|| anyhow!("Couldn't find nonce status."))?;
        let nonce_ok = nonce_ok
            .as_bool()
            .ok_or_else(|| anyhow!("Nonce status malformed"))?;
        if !nonce_ok {
            bail!("Report Data Mismatch");
        }

        Ok((claims, tee_class.to_string()))
    }

    fn evaluate_device_locally(
        &self,
        device: NvDeviceReportAndCert,
        expected_nonce_vec: Vec<u8>,
    ) -> Result<(TeeEvidenceParsedClaim, String)> {
        // Only Hopper GPU is supported for local verification.
        if device.arch != Architecture::Hopper {
            bail!("Device architecture not supported");
        }

        let b64_engine = base64::engine::general_purpose::STANDARD;

        let cert_chain_vec: Vec<u8> = b64_engine.decode(device.certificate)?;
        // Try hex::decode() to see if someone uses the original encoding still.
        // An Err Result suggests the evidence is base64 encoded so re-try with that.
        let report_vec: Vec<u8> = match hex::decode(&device.evidence) {
            Ok(evidence) => evidence,
            Err(e) => {
                debug!("Device evidence is not hex encoded (decoding failed with: {e}). Trying base64 decode.");
                b64_engine.decode(device.evidence)?
            }
        };

        let report = NvidiaAttestationReport::try_new(
            report_vec.as_slice(),
            HOPPER_SIGNATURE_LENGTH,
            cert_chain_vec.as_slice(),
            expected_nonce_vec.as_slice(),
        )?;
        trace!("{}", &report);

        // Build the device claims
        let device_claims =
            NvDeviceReportAndCertClaim::new(&device.arch, device.uuid.as_str(), &report);
        let value = serde_json::to_value(device_claims)
            .context("serializing NVIDIA evidence claims into JSON")?;

        Ok((value as TeeEvidenceParsedClaim, "gpu".to_string()))
    }
}

#[async_trait]
impl Verifier for Nvidia {
    #[instrument(skip_all, name = "Nvidia")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let devices: NvDeviceEvidence = serde_json::from_value(evidence)
            .context("Failed to deserialize the NVIDIA device evidence")?;
        let mut all_devices_claims: Vec<(TeeEvidenceParsedClaim, String)> = Vec::new();

        let ReportData::Value(expected_nonce) = expected_report_data else {
            bail!("Nvidia report data not provided");
        };
        let expected_nonce_vec: Vec<u8> =
            regularize_data(expected_nonce, SPDM_NONCE_SIZE, "REPORT_DATA", "NVIDIA");

        for device in devices.device_evidence_list {
            let claims = match &self.verifier_type {
                NvidiaVerifierType::Local => {
                    self.evaluate_device_locally(device, expected_nonce_vec.clone())?
                }
                NvidiaVerifierType::Remote(config) => {
                    self.evaluate_device_nras(device, expected_nonce_vec.clone(), config)
                        .await?
                }
            };

            all_devices_claims.push(claims);
        }

        if let Ok(ppcie_claims) = validate_ppcie(all_devices_claims.clone()) {
            all_devices_claims.push((ppcie_claims, "ppcie".to_string()));
        }

        Ok(all_devices_claims)
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;
    use tracing_subscriber::{fmt, EnvFilter};

    use super::*;

    /// Test the build of claims for a list of one nvidia device
    ///
    /// Reference for the claims values:
    ///  - Clone https://github.com/nvidia/nvtrust.git
    ///  - Follow the nvtrust/guest_tools/attestation_sdk/README.md to install requirements
    ///  - From nvtrust/guest_tools/gpu_verifiers/local_gpu_verifier/src, run:
    ///    python3 -m verifier.cc_admin --test_no_gpu --verbose
    #[test]
    fn test_build_claims_for_one_hopper_device() {
        fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_test_writer()
            .try_init()
            .expect("Failed to initialize tracing");

        let device_arch = Architecture::Hopper;
        let device_uuid: &str = "1111-2222-33333-444444-555555";

        let expected_nonce: &str =
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        let expected_nonce_vec: Vec<u8> = hex::decode(expected_nonce).unwrap();

        // The report certificate chain is stored in PEM format
        let cert_chain_bytes = include_bytes!("../../test_data/nvidia/hopper_cert_chain_case1.txt");

        // The attestation report is stored in text and hex encoded.
        let report_str = include_str!("../../test_data/nvidia/hopperAttestationReport.txt");
        let report_vec = hex::decode(report_str).unwrap();

        let report = NvidiaAttestationReport::try_new(
            report_vec.as_slice(),
            HOPPER_SIGNATURE_LENGTH,
            cert_chain_bytes,
            expected_nonce_vec.as_slice(),
        )
        .unwrap();

        let device_claims = NvDeviceReportAndCertClaim::new(&device_arch, device_uuid, &report);

        let value = serde_json::to_value(device_claims).unwrap();
        debug!("Nvidia device claims:\n{:#?}", &value);
        let json = serde_json::to_string(&value).unwrap();

        let expected_claim =
            include_str!("../../test_data/nvidia/hopperAttestationReport-claims.txt");

        assert_eq!(expected_claim.to_string(), json);
    }

    #[rstest]
    #[case::local_verifier("local", "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb", include_str!("../../test_data/nvidia/hopperAttestationReport.txt"), include_str!("../../test_data/nvidia/hopper_cert_chain_case1.txt"), Architecture::Hopper)]
    // Tests with the remote verifier are ignored to avoid putting strain on NRAS.
    // Please run these tests if you make any changes to the verifier.
    #[ignore]
    #[case::remote_verifier("remote", "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb", include_str!("../../test_data/nvidia/hopperAttestationReport.txt"), include_str!("../../test_data/nvidia/hopper_cert_chain_case1.txt"), Architecture::Hopper)]
    // Use the remote verifier with evidence from a CoCo CI run
    #[ignore]
    #[case::remote_verifier_coco("remote", "87d8e24ab336adafe228d49e83d745f6dba4ae505372b6a5704820856b343fece279b616efefc2aae21da80cf5581250", include_str!("../../test_data/nvidia/hopper_coco_report1.txt"), include_str!("../../test_data/nvidia/hopper_coco_certs1.txt"), Architecture::Hopper)]
    #[case::local_verifier_coco("local", "87d8e24ab336adafe228d49e83d745f6dba4ae505372b6a5704820856b343fece279b616efefc2aae21da80cf5581250", include_str!("../../test_data/nvidia/hopper_coco_report1.txt"), include_str!("../../test_data/nvidia/hopper_coco_certs1.txt"), Architecture::Hopper)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_evaluation(
        #[case] verifier_type: &str,
        // The expected report data (as hex) that was used to create the evidence.
        #[case] expected_report_data: &str,
        // HW evidence as a hex string
        #[case] report_str: &str,
        // Cert Chain from device as PEM
        #[case] cert_chain: &str,
        // Architecture of the device
        #[case] arch: Architecture,
    ) {
        let b64_engine = base64::engine::general_purpose::STANDARD;

        let device_uuid: &str = "1111-2222-33333-444444-555555";

        let expected_report_data_vec: Vec<u8> = hex::decode(expected_report_data).unwrap();

        let cert_chain = b64_engine.encode(cert_chain);

        // Create evidence as it would come from an attester
        let report = NvDeviceReportAndCert {
            arch,
            uuid: device_uuid.to_string(),
            evidence: report_str.to_string(),
            certificate: cert_chain.to_string(),
        };

        let evidence = NvDeviceEvidence {
            device_evidence_list: vec![report],
        };

        let evidence = serde_json::to_value(evidence).unwrap();

        let report_data = ReportData::Value(&expected_report_data_vec);
        let init_data = InitDataHash::NotProvided;

        let verifier_type = match verifier_type {
            "local" => NvidiaVerifierType::Local,
            "remote" => {
                NvidiaVerifierType::Remote(NvidiaRemoteVerifierConfig { verifier_url: None })
            }
            _ => panic!("Unknown verifier type."),
        };

        let verifier_config = Some(NvidiaVerifierConfig {
            verifier: verifier_type,
        });
        let verifier = Nvidia::new(verifier_config).await.unwrap();
        let claims = verifier
            .evaluate(evidence, &report_data, &init_data)
            .await
            .unwrap();

        println!("{:?}", serde_json::to_string(&claims));
    }
}
