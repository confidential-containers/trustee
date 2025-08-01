// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use log::warn;
use openssl::x509::X509;
use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use p384::pkcs8::DecodePublicKey;

use super::{regularize_data, ReportData};
use super::spdm_request::{SpdmGetMeasurementRequest, SPDM_GET_MEASUREMENT_REQUEST_SIZE};
use super::spdm_response::SpdmGetMeasurementsResponse;

pub struct NvidiaAttestationReport {
    pub request: SpdmGetMeasurementRequest,
    pub response: SpdmGetMeasurementsResponse
}

impl NvidiaAttestationReport {
    /// Decode NvidiaAttestationReport from the layout:
    ///
    /// OFFSET   - FIELD                          - SIZE(in bytes)
    /// 0        - SPDM_GET_MEASUREMENT_REQUEST   - 37
    /// 37       - SPDM_GET_MEASUREMENT_RESPONSE  - vary
    pub fn decode(report_bytes: &[u8], signature_length: &usize) -> Result<Self> {
        let (request_bytes, response_bytes) = report_bytes
            .split_at_checked(SPDM_GET_MEASUREMENT_REQUEST_SIZE)
            .ok_or(anyhow!("Attestation report data is too small"))?;

        Ok( Self {
            request: SpdmGetMeasurementRequest::decode(request_bytes)?,
            response: SpdmGetMeasurementsResponse::decode(response_bytes, signature_length)?,
        } )
    }

    pub fn verify_signature(report_bytes: &[u8], signature_length: &usize, signing_cert: &X509) -> Result<()> {
        let signed_data = report_bytes
            .get(..report_bytes.len()-signature_length)
            .ok_or(anyhow!("signed data overflow"))?;
        
        let signature_bytes = &report_bytes[report_bytes.len()-signature_length..];
        let signature = Signature::from_slice(signature_bytes)?;

        // Extract EC public key from certificate
        let public_key = signing_cert
            .public_key()?
            .public_key_to_der()?;

        let verifying_key = VerifyingKey::from_public_key_der(public_key.as_slice())?;
        verifying_key.verify(signed_data, &signature)
            .map_err(|e| anyhow!(e.to_string()))
    }

    pub fn validate_freshness(self, report_data: &ReportData) -> Result<()> {
        if let ReportData::Value(expected_report_data) = report_data {
            let expected_report_data: Vec<u8> =
                regularize_data(expected_report_data, 32, "REPORT_DATA", "NVIDIA");
            if expected_report_data != self.request.nonce {
                warn!(
                    "Report data mismatch. Given: {}, Expected: {}",
                    hex::encode(self.request.nonce),
                    hex::encode(expected_report_data)
                );
                bail!("Report Data Mismatch");
            }
        };
        Ok(())
    }
}