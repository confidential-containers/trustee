// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

pub mod cert_chain;
pub mod report;
pub mod spdm_request;
pub mod spdm_response;

use anyhow::{bail, Result};
use async_trait::async_trait;
use base64::Engine;
use log::trace;
use nvml_wrapper::enums::device::DeviceArchitecture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use super::*;
use crate::nvidia::report::NvidiaAttestationReport;

const HOPPER_SIGNATURE_LENGTH: usize = 96;

/// Only SPDM Version 1.1 is supported
pub const SPDM_VERSION_SUPPORTED: u8 = 0x11;
pub const SPDM_NONCE_SIZE: usize = 32;

// Only measurements encoded in the DMTF_MEASUREMENT layout are supported
pub const DMTF_MEASUREMENT_SPECIFICATION_VALUE: u8 = 1;

#[derive(Default, Debug)]
pub struct Nvidia {}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct NvidiaVerifierConfig {}

#[derive(Debug, Default, Deserialize)]
struct NvDeviceEvidence {
    device_evidence_list: Vec<NvDeviceReportAndCert>,
}

#[derive(Debug, Deserialize)]
struct NvDeviceReportAndCert {
    arch: DeviceArchitecture,
    uuid: String,
    evidence: String,
    certificate: String,
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
        device_arch: &DeviceArchitecture,
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

impl Nvidia {
    pub fn new(_config: Option<NvidiaVerifierConfig>) -> Self {
        Nvidia {}
    }
}

#[async_trait]
impl Verifier for Nvidia {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let devices: NvDeviceEvidence = serde_json::from_value(evidence)
            .context("Failed to deserialize the NVIDIA device evidence")?;
        let mut all_devices_claims: Vec<(TeeEvidenceParsedClaim, String)> = Vec::new();

        for device in devices.device_evidence_list {
            // Only Hopper GPU is supported.
            if device.arch != DeviceArchitecture::Hopper {
                bail!("Device architecture not supported");
            }

            let b64_engine = base64::engine::general_purpose::STANDARD;

            let cert_chain_vec: Vec<u8> = b64_engine.decode(device.certificate)?;
            let report_vec: Vec<u8> = hex::decode(device.evidence)?;

            let ReportData::Value(expected_nonce) = expected_report_data else {
                bail!("Nvidia report data not provided");
            };
            let expected_nonce_vec: Vec<u8> =
                regularize_data(expected_nonce, SPDM_NONCE_SIZE, "REPORT_DATA", "NVIDIA");

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

            all_devices_claims.push((value as TeeEvidenceParsedClaim, "gpu".to_string()));
        }

        Ok(all_devices_claims)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

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
        env_logger::init();

        let device_arch = DeviceArchitecture::Hopper;
        let device_uuid: &str = "1111-2222-33333-444444-555555";

        let expected_nonce: &str =
            "931d8dd0add203ac3d8b4fbde75e115278eefcdceac5b87671a748f32364dfcb";
        let expected_nonce_vec: Vec<u8> = hex::decode(expected_nonce).unwrap();

        // The report certificate chain is stored in PERM format
        let cert_chain_bytes = include_bytes!("../../test_data/nvidia/hopper_cert_chain_case1.txt");

        // The attestation report is stored in text and hex encoded.
        let report_str = include_str!("../../test_data/nvidia/hopperAttestationReport.txt");
        let report_vec = hex::decode(report_str).unwrap();

        let report = NvidiaAttestationReport::try_new(
            report_vec.as_slice(),
            HOPPER_SIGNATURE_LENGTH,
            cert_chain_bytes,
            &expected_nonce_vec.as_slice(),
        )
        .unwrap();

        let device_claims =
            NvDeviceReportAndCertClaim::new(&device_arch, &device_uuid.to_string(), &report);

        let value = serde_json::to_value(device_claims).unwrap();
        debug!("Nvidia device claims:\n{:#?}", &value);
        let json = serde_json::to_string(&value).unwrap();

        let _ = fs::write("hopperAttestationReport-claims.txt", &json).unwrap();

        let expected_claim =
            include_str!("../../test_data/nvidia/hopperAttestationReport-claims.txt");

        assert_eq!(expected_claim.to_string(), json);
    }
}
