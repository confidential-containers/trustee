// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::Result;
use thiserror::Error;
use log::{debug, warn};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use codicon::Decoder;
use csv_rs::{
    api::guest::{AttestationReport, Body},
    certs::{ca, csv, Verifiable},
};
use serde_json::json;

#[derive(Serialize, Deserialize)]
struct CertificateChain {
    hsk: ca::Certificate,
    cek: csv::Certificate,
    pek: csv::Certificate,
}

#[derive(Serialize, Deserialize)]
struct CsvEvidence {
    attestation_report: AttestationReport,
    cert_chain: CertificateChain,
    serial_number: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum CsvError {
    #[error("REPORT_DATA is different from that in CSV Quote")]
    ReportDataMismatch,
    #[error("Serde json error: Deserialize Quote failed")]
    SerdeJson(#[from] serde_json::Error),
    #[error("IO error")]
    IO(#[from] std::io::Error),
    #[error("HRK cert Signature verification failed: {0}")]
    HRKSignatureVerification(String),
    #[error("HSK cert Signature validation failed: {0}")]
    HSKSignatureValidation(String),
    #[error("CEK cert Signature validation failed: {0}")]
    CEKSignatureValidation(String),
    #[error("PEK cert Signature validation failed: {0}")]
    PEKSignatureValidation(String),
    #[error("Attestation Report Signature validation failed: {0}")]
    AttestationReportSignatureValidation(String),
    #[error("Parse TEE evidence failed: {0}")]
    ParseTeeEvidence(String),
    #[error("Verify report signature failed: {0}")]
    VerifyReportSignature(String),
    #[error("anyhow error")]
    Anyhow(#[from] anyhow::Error),
}

pub const HRK: &[u8] = include_bytes!("hrk.cert");

#[derive(Debug, Default)]
pub struct CsvVerifier {}

#[async_trait]
impl Verifier for CsvVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim, CsvError> {
        let result = async {
        let tee_evidence =
            serde_json::from_slice::<CsvEvidence>(evidence)?;

        verify_report_signature(&tee_evidence.attestation_report, &tee_evidence.cert_chain)?;

        let report_raw = restore_attestation_report(tee_evidence.attestation_report)?;

        if let ReportData::Value(expected_report_data) = expected_report_data {
            debug!("Check the binding of REPORT_DATA.");
            let expected_report_data =
                regularize_data(expected_report_data, 64, "REPORT_DATA", "CSV");
            if expected_report_data != report_raw.body.report_data {
                return Err(CsvError::ReportDataMismatch);
            }
        }

        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("CSV does not support init data hash mechanism. skip.");
        }

        parse_tee_evidence(&report_raw, tee_evidence.serial_number.clone())
        }
        .await;

        result.map_err(CsvError::from)
    }
}

fn verify_report_signature(
    attestation_report: &AttestationReport,
    cert_chain: &CertificateChain,
) -> Result<(), CsvError> {
    // Verify certificate chain
    let hrk = ca::Certificate::decode(&mut &HRK[..], ())?;
    (&hrk, &hrk)
        .verify()
        .map_err(|err| CsvError::HRKSignatureVerification(err.to_string()))?;
    (&hrk, &cert_chain.hsk)
        .verify()
        .map_err(|err| CsvError::HSKSignatureValidation(err.to_string()))?;
    (&cert_chain.hsk, &cert_chain.cek)
        .verify()
        .map_err(|err| CsvError::CEKSignatureValidation(err.to_string()))?;
    (&cert_chain.cek, &cert_chain.pek)
        .verify()
        .map_err(|err| CsvError::PEKSignatureValidation(err.to_string()))?;

    // Verify the TEE Hardware signature.

    (&cert_chain.pek, attestation_report)
        .verify()
        .map_err(|err| CsvError::AttestationReportSignatureValidation(err.to_string()))?;

    Ok(()).map_err(|err| CsvError::VerifyReportSignature(err.to_string()))
}

fn xor_with_anonce(data: &mut [u8], anonce: &u32) {
    let mut anonce_array = [0u8; 4];
    anonce_array[..].copy_from_slice(&anonce.to_le_bytes());

    for (index, item) in data.iter_mut().enumerate() {
        *item ^= anonce_array[index % 4];
    }
}

fn restore_attestation_report(report: AttestationReport) -> Result<AttestationReport> {
    let body = &report.body;
    let mut user_pubkey_digest = body.user_pubkey_digest;
    xor_with_anonce(&mut user_pubkey_digest, &report.anonce);
    let mut vm_id = body.vm_id;
    xor_with_anonce(&mut vm_id, &report.anonce);
    let mut vm_version = body.vm_version;
    xor_with_anonce(&mut vm_version, &report.anonce);
    let mut report_data = body.report_data;
    xor_with_anonce(&mut report_data, &report.anonce);
    let mut mnonce = body.mnonce;
    xor_with_anonce(&mut mnonce, &report.anonce);
    let mut measure = body.measure;
    xor_with_anonce(&mut measure, &report.anonce);

    let policy = report.body.policy.xor(&report.anonce);

    Ok(AttestationReport {
        body: Body {
            user_pubkey_digest,
            vm_id,
            vm_version,
            report_data,
            mnonce,
            measure,
            policy,
        },
        ..report
    })
}

// Dump the CSV information from the report.
fn parse_tee_evidence(
    report: &AttestationReport,
    serial_number: Vec<u8>,
) -> Result<TeeEvidenceParsedClaim, CsvError> {
    let body = &report.body;
    let claims_map = json!({
        // policy fields
        "policy_nodbg": format!("{}",body.policy.nodbg()),
        "policy_noks": format!("{}", body.policy.noks()),
        "policy_es": format!("{}", body.policy.es()),
        "policy_nosend": format!("{}", body.policy.nosend()),
        "policy_domain": format!("{}", body.policy.domain()),
        "policy_csv": format!("{}", body.policy.csv()),
        "policy_csv3": format!("{}", body.policy.csv3()),
        "policy_asid_reuse": format!("{}", body.policy.asid_reuse()),
        "policy_hsk_version": format!("{}", body.policy.hsk_version()),
        "policy_cek_version": format!("{}", body.policy.cek_version()),
        "policy_api_major": format!("{}", body.policy.api_major()),
        "policy_api_minor": format!("{}", body.policy.api_minor()),

        // launch info inject with pdh and session data
        "user_pubkey_digest": format!("{}", base64::engine::general_purpose::STANDARD.encode(body.user_pubkey_digest)),
        "vm_id": format!("{}", base64::engine::general_purpose::STANDARD.encode(body.vm_id)),
        "vm_version": format!("{}", base64::engine::general_purpose::STANDARD.encode(body.vm_version)),

        // Chip ID
        "serial_number": format!("{}", base64::engine::general_purpose::STANDARD.encode(serial_number)),

        // measurement
        "measurement": format!("{}", base64::engine::general_purpose::STANDARD.encode(body.measure)),

        // report data
        "report_data": format!("{}", base64::engine::general_purpose::STANDARD.encode(body.report_data)),
    });

    Ok(claims_map as TeeEvidenceParsedClaim).map_err(|err| CsvError::ParseTeeEvidence(err.to_string()))
}
