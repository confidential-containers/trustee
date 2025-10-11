// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use openssl::x509::X509;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;
use serde_json::Value;
use std::fmt;
use tracing::{info, warn};

use super::spdm_request::{SpdmGetMeasurementRequest, SPDM_GET_MEASUREMENT_REQUEST_SIZE};
use super::spdm_response::SpdmGetMeasurementsResponse;
use crate::nvidia::cert_chain::NvidiaCertificateChain;
use crate::nvidia::spdm_response::OpaqueDataType;

#[derive(Debug, Default)]
pub struct NvidiaAttestationReport {
    pub request: SpdmGetMeasurementRequest,
    pub response: SpdmGetMeasurementsResponse,
}

impl fmt::Display for NvidiaAttestationReport {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Nvidia Attestation Report:")?;
        writeln!(f, "{}", &self.request)?;
        write!(f, "{}", &self.response)
    }
}

impl NvidiaAttestationReport {
    pub fn try_new(
        report_bytes: &[u8],
        report_signature_length: usize,
        cert_chain_bytes: &[u8],
        expected_nonce: &[u8],
    ) -> Result<Self> {
        let (report, report_size) =
            NvidiaAttestationReport::decode(report_bytes, &report_signature_length)?;

        let cert_chain = NvidiaCertificateChain::decode(cert_chain_bytes)?;

        let leaf_cert = cert_chain.get_leaf_certificate()?;

        let signed_data_size = report_size
            .checked_sub(report_signature_length)
            .ok_or(anyhow!("Nvidia report size too small"))?;

        let signed_data = report_bytes
            .get(..signed_data_size)
            .ok_or(anyhow!("Nvidia report signed data overflow"))?;

        // Verify report signature
        Self::verify_signature(signed_data, report.response.signature.as_slice(), leaf_cert)?;
        info!("Report signature verified");

        // Verify report certificate chain
        cert_chain.verify(report.get_fwid()?)?;
        info!("Report certificate chain verified");

        // Verify report nonce
        report.validate_nonce(expected_nonce)?;
        info!("Report nonce validated");

        Ok(report)
    }

    fn get_fwid(&self) -> Result<&String> {
        let fwid_value = self
            .response
            .opaque_data
            .get(&OpaqueDataType::Fwid.to_string())
            .ok_or(anyhow!("Nvidia report fwid not found"))?;

        let Value::String(fwid) = fwid_value else {
            bail!("Nvidia report fwid value mismatch");
        };
        Ok(fwid)
    }

    /// Decode NvidiaAttestationReport from the layout:
    ///
    /// OFFSET   - FIELD                          - SIZE(in bytes)
    /// 0        - SPDM_GET_MEASUREMENT_REQUEST   - 37
    /// 37       - SPDM_GET_MEASUREMENT_RESPONSE  - vary
    fn decode(report_bytes: &[u8], signature_length: &usize) -> Result<(Self, usize)> {
        let (request_bytes, response_bytes) = report_bytes
            .split_at_checked(SPDM_GET_MEASUREMENT_REQUEST_SIZE)
            .ok_or(anyhow!("Attestation report data is too small"))?;

        let (request, request_size) = SpdmGetMeasurementRequest::decode(request_bytes)?;
        let (response, response_size) =
            SpdmGetMeasurementsResponse::decode(response_bytes, signature_length)?;

        let report = Self { request, response };
        let report_size = request_size + response_size;

        Ok((report, report_size))
    }

    fn verify_signature(
        signed_bytes: &[u8],
        signature_bytes: &[u8],
        signing_cert: &X509,
    ) -> Result<()> {
        let signature = Signature::from_slice(signature_bytes)?;

        // Extract EC public key from certificate
        let public_key = signing_cert.public_key()?.public_key_to_der()?;

        let verifying_key = VerifyingKey::from_public_key_der(public_key.as_slice())?;

        verifying_key
            .verify(signed_bytes, &signature)
            .map_err(|e| anyhow!("NVIDIA report signature failed: {}", e))
    }

    pub fn validate_nonce(&self, expected_nonce: &[u8]) -> Result<()> {
        if expected_nonce != self.request.nonce {
            warn!(
                "Nvidia report nonce mismatch. Given nonce: {}, Expected: {}",
                hex::encode(self.request.nonce),
                hex::encode(expected_nonce)
            );
            bail!("Nvidia report nonce mismatch");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use openssl::x509::X509;

    use crate::nvidia::{report::NvidiaAttestationReport, HOPPER_SIGNATURE_LENGTH};

    #[test]
    fn test_verify_report_signature() {
        // The attestation report is stored in text and hex encoded.
        let report_str = include_str!("../../test_data/nvidia/hopperAttestationReport.txt");
        let report_vec = hex::decode(report_str).unwrap();

        let (report, report_size) =
            NvidiaAttestationReport::decode(report_vec.as_slice(), &HOPPER_SIGNATURE_LENGTH)
                .unwrap();

        let signing_cert_bytes = include_bytes!("../../test_data/nvidia/hopper_signing_cert.pem");
        let signing_cert = X509::from_pem(signing_cert_bytes).unwrap();

        let signed_data_size = report_size.checked_sub(HOPPER_SIGNATURE_LENGTH).unwrap();

        let signed_data = report_vec.get(..signed_data_size).unwrap();

        NvidiaAttestationReport::verify_signature(
            signed_data,
            report.response.signature.as_slice(),
            &signing_cert,
        )
        .unwrap();
    }
}
