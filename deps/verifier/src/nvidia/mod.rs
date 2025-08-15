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
use nvml_wrapper::{enums::device::DeviceArchitecture};
use serde::{Deserialize, Serialize};

use crate::nvidia::spdm_response::{SpdmGetMeasurementsResponse, MeasurementBlock};
use crate::nvidia::cert_chain::NvidiaCertificateChain;
use crate::nvidia::report::NvidiaAttestationReport;
use super::*;

const HOPPER_SIGNATURE_LENGTH: usize = 96;

/// Only SPDM Version 1.1 is supported
pub const SPDM_VERSION_SUPPORTED: u8 = 0x11;

// Only measurements encoded in the DMTF_MEASUREMENT layout are supported
pub const DMTF_MEASUREMENT_SPECIFICATION_VALUE: u8 = 1;

#[derive(Default, Debug)]
pub struct Nvidia {}

#[derive(Debug, Default, Deserialize)]
struct NvDeviceEvidence {
    device_evidence_list: Vec<NvDeviceReportAndCert>,
}

#[derive(Debug, Deserialize)]
struct NvDeviceReportAndCert {
    arch: DeviceArchitecture,
    uuid: String,
    evidence: String,
    certificate_chain: String,
}

#[derive(Debug, Default, Serialize)]
struct NvDeviceEvidenceClaim {
    devices_claims: Vec<NvDeviceReportAndCertClaim>,
}

#[derive(Default, Debug, Serialize)]
pub struct NvDeviceReportAndCertClaim {
    arch: String,
    uuid: String,
    measurement_blocks: Vec<MeasurementBlockClaim>,
    opaque_data: OpaqueDataClaim,
}

#[derive(Default, Debug, Serialize)]
struct SpdmGetMeasurementsResponseClaim {
    measurements: Vec<MeasurementBlockClaim>,
    opaque_data: OpaqueDataClaim,
}

#[derive(Debug, Default, Serialize)]
struct MeasurementBlockClaim {
    index: u8,
    measurement_type: u8,
    measurement_value: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[allow(non_snake_case)]
struct OpaqueDataClaim {
    #[serde(default)]
    OPAQUE_FIELD_ID_CERT_ISSUER_NAME: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_DRIVER_VERSION: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_GPU_INFO: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_SKU: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_VBIOS_VERSION: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_MANUFACTURER_ID: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_TAMPER_DETECTION: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_SMC: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_VPR: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_NVDEC0_STATUS: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_MSRSCNT: Vec<u32>,
    #[serde(default)]
    OPAQUE_FIELD_ID_CPRINFO: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_BOARD_ID: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_CHIP_SKU: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_CHIP_SKU_MOD: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_PROJECT: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_PROJECT_SKU: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_PROJECT_SKU_MOD: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_FWID: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_SWITCH_PDI: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_FLOORSWEPT_PORTS: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_POSITION_ID: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS: String,
    #[serde(default)]
    OPAQUE_FIELD_ID_GPU_LINK_CONN: String,
}

impl NvDeviceReportAndCertClaim {
    fn try_build_from(device_arch: &DeviceArchitecture, device_uuid: &str, attestation_report: &NvidiaAttestationReport) -> Result<Self> {
        let response_claim = SpdmGetMeasurementsResponseClaim::try_from(&attestation_report.response)?;

        Ok(
            Self {
                arch: device_arch.to_string(),
                uuid: device_uuid.to_string(),
                measurement_blocks: response_claim.measurements,
                opaque_data: response_claim.opaque_data,
            }
        )
    }
}

impl TryFrom<&MeasurementBlock> for MeasurementBlockClaim {
    type Error = Error;

    fn try_from(value: &MeasurementBlock) -> Result<Self> {
        let claim = MeasurementBlockClaim {
                index: value.index,
                measurement_type: value.measurement.value_type,
                measurement_value: hex::encode(value.measurement.value.clone()),
        };
        Ok(claim)
    }
}

impl TryFrom<&SpdmGetMeasurementsResponse> for SpdmGetMeasurementsResponseClaim {
    type Error = Error;

    fn try_from(response: &SpdmGetMeasurementsResponse) -> Result<Self> {
        // Measurements
        let mut measurements: Vec<MeasurementBlockClaim> = Vec::with_capacity(response.measurement_record.len());
        for m in &response.measurement_record {
            measurements.push(MeasurementBlockClaim::try_from(m)?);
        }

        // Opaque data        
        let opaque_data_string = serde_json::to_string(&response.opaque_data)?;
        let opaque_data: OpaqueDataClaim = serde_json::from_str(opaque_data_string.as_str())?;

        Ok( SpdmGetMeasurementsResponseClaim { measurements, opaque_data } )
    }
}

#[async_trait]
impl Verifier for Nvidia {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        _expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let devices: NvDeviceEvidence = serde_json::from_value(evidence).context("Failed to deserialize the NVIDIA device evidence")?;
        let mut all_claims = NvDeviceEvidenceClaim::default();

        for device in devices.device_evidence_list {
            // Only Hopper is supported
            if device.arch != DeviceArchitecture::Hopper {
                bail!("Device architecture not supported");
            }

            let cert_chain_vec: Vec<u8> = hex::decode(device.certificate_chain)?;
            let report_vec: Vec<u8> = hex::decode(device.evidence)?;
            
            let cert_chain = NvidiaCertificateChain::decode(cert_chain_vec.as_slice())?;
            let report = NvidiaAttestationReport::decode(&report_vec.as_slice(), &HOPPER_SIGNATURE_LENGTH)?;

            // Build the claims first as we need the FwId from the report to verify the certificate chain
            let device_claims = NvDeviceReportAndCertClaim::try_build_from(&device.arch, device.uuid.as_str(), &report)?;

            // Verify certificate chain
            let signing_cert = cert_chain
                .verify(&device_claims.opaque_data.OPAQUE_FIELD_ID_FWID)?;

            // Verify attestation report freshness
            report.validate_freshness(expected_report_data)?;

            // TODO! Check if the singing certificate has been revoked

            // Verify the attestation report signature using the report_bytes rather than the parsed report.
            // Otherwise, we would need to ensure that they have the same representation in memory.
            NvidiaAttestationReport::verify_signature(report_vec.as_slice(), &HOPPER_SIGNATURE_LENGTH, signing_cert)?;

            all_claims.devices_claims.push(device_claims);
        }
      
        let value = serde_json::to_value(all_claims).context("serializing NVIDIA evidence claims into JSON")?;

        Ok((value as TeeEvidenceParsedClaim, "nvidia".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::nvidia::cert_chain::get_fwid_from_cert;

    use super::*;
    use openssl::x509::X509;
    use rstest::rstest;

    const FWID: &str = "f5c384aebb579217a2c66b17ed0f28e6a9b8d639041acd7b4721cec004f7275494ba94bb5cdfdb3055ee051762b1f75d";

    /// Test the build of claims for a list of one nvidia device
    /// 
    /// Reference for the claims values:
    ///  - Clone https://github.com/nvidia/nvtrust.git
    ///  - Follow the nvtrust/guest_tools/attestation_sdk/README.md to install requirements
    ///  - From nvtrust/guest_tools/attestation_sdk/tests/end_to_end/hardware, run:
    ///    python3 -m verifier.cc_admin --test_no_gpu --verbose
    #[test]
    fn test_build_claims_for_one_hopper_device() {
        let device_arch  = DeviceArchitecture::Hopper;
        let device_uuid: &str = "1111-2222-33333-444444-555555";

        // The attestation report is stored in text and hex encoded.
        let report_str = include_str!("../../test_data/nvidia/hopperAttestationReport.txt");
        let report_vec = hex::decode(report_str).unwrap();

        let report = NvidiaAttestationReport::decode(report_vec.as_slice(), &HOPPER_SIGNATURE_LENGTH).unwrap();

        let device_claims = NvDeviceReportAndCertClaim::try_build_from(&device_arch, &device_uuid.to_string(), &report).unwrap();

        let mut all_claims = NvDeviceEvidenceClaim::default();
        all_claims.devices_claims.push(device_claims);
        
        let value = serde_json::to_value(all_claims).unwrap();
        let json = serde_json::to_string(&value).unwrap();

        let _ = fs::write(
            "hopperAttestationReport-claims.txt",
            &json,
        ).unwrap();

        let expected_claim = include_str!("../../test_data/nvidia/hopperAttestationReport-claims.txt");

        assert_eq!(expected_claim.to_string(), json);
    }

    #[test]
    fn test_verify_hopper_report_signature() {
        // Certificate chain is in PERM format
        let cert_chain_bytes = include_bytes!("../../test_data/nvidia/hopper_cert_chain_case1.txt");
        
        // The attestation report is stored in text and hex encoded. 
        let report_str = include_str!("../../test_data/nvidia/hopperAttestationReport.txt");
        let report_bytes = hex::decode(report_str).unwrap();

        let cert_chain = NvidiaCertificateChain::decode(cert_chain_bytes).unwrap();
        let leaf_cert = cert_chain.get_leaf_certificate().unwrap();

        let status = NvidiaAttestationReport::verify_signature(&report_bytes, &HOPPER_SIGNATURE_LENGTH, leaf_cert);

        assert!(status.is_ok())
    }

    #[test]
    // The FwId is last 48 bytes of the "2.23.133.5.4.1" extension
    // Command: openssl asn1parse -i -in hopper_singing_cert.pem
    fn test_parse_fwid_from_certificate() {
        let signing_cert = X509::from_pem(include_bytes!("../../test_data/nvidia/hopper_signing_cert.pem"))
            .map_err(|_| anyhow!("hopper_singing_cert.pem failed to read"))
            .unwrap();
        let fwid = get_fwid_from_cert(&signing_cert).unwrap();
        assert_eq!(FWID.to_string(), fwid);
    }

    #[rstest]
    // Case1: Valid Hopper certificate chain
    #[case(1, FWID, true)]
    // Case2: Bad Hopper certificate chain. Only the root CA
    #[case(2, FWID, false)]
    // Case3: Bad Hopper certificate chain. Missing intermediate CA
    #[case(3, FWID, false)]
    // Case4: Bad Hopper certificate chain. Missing actual signing certificate
    #[case(4, FWID, false)]
    fn test_verify_certificate_chain_for_hopper(
        #[case] case_number: usize,
        #[case] expected_fwid: &str,
        #[case] is_expected_to_pass: bool,
    ) {
        let cert_chain_str = match case_number {
            1 => include_str!("../../test_data/nvidia/hopper_cert_chain_case1.txt"),
            2 => include_str!("../../test_data/nvidia/hopper_cert_chain_case2.txt"),
            3 => include_str!("../../test_data/nvidia/hopper_cert_chain_case3.txt"),
            4 => include_str!("../../test_data/nvidia/hopper_cert_chain_case4.txt"),
            _ => "case number does not exist",
        };
        let cert_chain = NvidiaCertificateChain::decode(cert_chain_str.as_bytes()).unwrap();

        assert_eq!(cert_chain.verify(expected_fwid).is_ok(), is_expected_to_pass);
    }
}