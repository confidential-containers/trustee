// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use base64::Engine;
use eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, ReferenceMeasurement};
use reqwest::{get, Response as ReqwestResponse, StatusCode};
use std::{io::Cursor, path::Path};
use tokio::fs;

use thiserror::Error;
use tracing::{debug, info, instrument, warn};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use codicon::Decoder;
use csv_rs::{
    api::guest::{AttestationReport, AttestationReportWrapper},
    certs::{ca, csv, Verifiable},
};
use serde_json::json;

const DEFAULT_CSV_CERT_DIR: &str = "/opt/hygon/csv";

#[derive(Serialize, Deserialize)]
struct HskCek {
    hsk: ca::Certificate,
    cek: csv::Certificate,
}

#[derive(Serialize, Deserialize)]
struct CertificateChain {
    #[serde(skip_serializing_if = "Option::is_none")]
    hsk_cek: Option<HskCek>,

    pek: csv::Certificate,
}

#[derive(Serialize, Deserialize)]
struct CsvEvidence {
    attestation_report: AttestationReportWrapper,

    cert_chain: CertificateChain,

    // Base64 Encoded CSV Serial Number (Used to identify HYGON chip ID)
    serial_number: Vec<u8>,

    /// Base64 encoded Eventlog
    /// This might include the
    /// - CCEL: <https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table>
    /// - AAEL in TCG2 encoding: <https://github.com/confidential-containers/trustee/blob/main/kbs/docs/confidential-containers-eventlog.md>
    cc_eventlog: Option<String>,
}

#[derive(Error, Debug)]
pub enum CsvError {
    #[error("REPORT_DATA is different from that in CSV Quote")]
    ReportDataMismatch,
    #[error("Deserialize Quote failed")]
    DesearizeQuoteFailed(#[source] serde_json::Error),
    #[error(transparent)]
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
}

pub const HRK: &[u8] = include_bytes!("hrk.cert");

#[derive(Debug, Default)]
pub struct CsvVerifier {}

#[async_trait]
impl Verifier for CsvVerifier {
    #[instrument(skip_all, name = "Hygon CSV")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let CsvEvidence {
            attestation_report: report_wrapper,
            cert_chain,
            serial_number,
            cc_eventlog,
        } = serde_json::from_value(evidence).context("Deserialize Quote failed.")?;

        let report = AttestationReport::try_from(&report_wrapper)?;
        let chip_id = std::str::from_utf8(&serial_number)?.trim_end_matches('\0');

        let (hsk, cek, pek) = match cert_chain.hsk_cek {
            Some(hsk_cek) => {
                debug!("HSK and CEK are both included in the evidence");
                (hsk_cek.hsk, hsk_cek.cek, cert_chain.pek)
            }
            None => {
                let cert_data = match try_load_hskcek_offline(chip_id).await {
                    Some(cert_data) => cert_data,
                    None => download_hskcek_from_kds(chip_id).await?,
                };

                debug!(
                    hsk_cek = cert_data
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<String>>()
                        .join(""),
                    "Load HSK and CEK",
                );

                let mut reader = Cursor::new(cert_data);
                let hsk = ca::Certificate::decode(&mut reader, ())?;
                let cek = csv::Certificate::decode(&mut reader, ())?;
                let pek = cert_chain.pek;
                (hsk, cek, pek)
            }
        };

        verify_report_signature(&report, hsk, cek, pek)?;

        if let ReportData::Value(expected_report_data) = expected_report_data {
            debug!("Check the binding of REPORT_DATA.");
            let expected_report_data =
                regularize_data(expected_report_data, 64, "REPORT_DATA", "CSV");
            if expected_report_data != report.tee_info().report_data() {
                return Err(CsvError::ReportDataMismatch.into());
            }
        }

        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("CSV does not support init data hash mechanism. skip.");
        }

        match &report {
            AttestationReport::V1(attestation_report_v1) => {
                let anonce = attestation_report_v1.tee_info.anonce;
                let policy = attestation_report_v1.tee_info.policy.xor(&anonce);
                let claims = json!({
                    "version": "1",
                    "policy": {
                        "nodbg": policy.nodbg(),
                        "noks": policy.noks(),
                        "es": policy.es(),
                        "nosend": policy.nosend(),
                        "domain": policy.domain(),
                        "csv": policy.csv(),
                        "csv3": policy.csv3(),
                        "asid_reuse": policy.asid_reuse(),
                        "hsk_version": policy.hsk_version(),
                        "cek_version": policy.cek_version(),
                        "api_major": policy.api_major(),
                        "api_minor": policy.api_minor(),
                    },
                    "user_pubkey_digest": hex::encode(report.tee_info().user_pubkey_digest()),
                    "vm_id": hex::encode(report.tee_info().vm_id()),
                    "vm_version": hex::encode(report.tee_info().vm_version()),
                    "report_data": hex::encode(report.tee_info().report_data()),
                    "mnonce": hex::encode(report.tee_info().mnonce()),
                    "measure": hex::encode(report.tee_info().measure()),
                    "sig_usage": hex::encode(report.tee_info().sig_usage().to_le_bytes()),
                    "sig_algo": hex::encode(report.tee_info().sig_algo().to_le_bytes()),
                    "anonce": hex::encode(anonce.to_le_bytes()),
                    "serial_number": String::from_utf8(serial_number)?.trim_end_matches('\0'),
                });
                Ok(vec![(claims, "cpu".to_string())])
            }
            AttestationReport::V2(attestation_report_v2) => {
                let policy = attestation_report_v2.tee_info.policy;
                let mut claims = json!({
                    "version": "2",
                    "policy": {
                        "nodbg": policy.nodbg(),
                        "noks": policy.noks(),
                        "es": policy.es(),
                        "nosend": policy.nosend(),
                        "domain": policy.domain(),
                        "csv": policy.csv(),
                        "csv3": policy.csv3(),
                        "asid_reuse": policy.asid_reuse(),
                        "hsk_version": policy.hsk_version(),
                        "cek_version": policy.cek_version(),
                        "api_major": policy.api_major(),
                        "api_minor": policy.api_minor(),
                    },
                    "user_pubkey_digest": hex::encode(report.tee_info().user_pubkey_digest()),
                    "vm_id": hex::encode(report.tee_info().vm_id()),
                    "vm_version": hex::encode(report.tee_info().vm_version()),
                    "report_data": hex::encode(report.tee_info().report_data()),
                    "mnonce": hex::encode(report.tee_info().mnonce()),
                    "measure": hex::encode(report.tee_info().measure()),
                    "sig_usage": hex::encode(report.tee_info().sig_usage().to_le_bytes()),
                    "sig_algo": hex::encode(report.tee_info().sig_algo().to_le_bytes()),
                    "build": attestation_report_v2.tee_info.build,
                    "rtmr_version": attestation_report_v2.tee_info.rtmr_version,
                    "reserved0": hex::encode(attestation_report_v2.tee_info.reserved0),
                    "rtmr0": hex::encode(attestation_report_v2.tee_info.rtmr0),
                    "rtmr1": hex::encode(attestation_report_v2.tee_info.rtmr1),
                    "rtmr2": hex::encode(attestation_report_v2.tee_info.rtmr2),
                    "rtmr3": hex::encode(attestation_report_v2.tee_info.rtmr3),
                    "rtmr4": hex::encode(attestation_report_v2.tee_info.rtmr4),
                    "reserved1": hex::encode(attestation_report_v2.tee_info.reserved1),
                    "serial_number": String::from_utf8(serial_number)?.trim_end_matches('\0'),
                });
                if let Some(el) = cc_eventlog {
                    let ccel_data = base64::engine::general_purpose::STANDARD.decode(el)?;
                    let ccel = CcEventLog::try_from(ccel_data)
                        .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
                    let compare_obj: Vec<ReferenceMeasurement> = vec![
                        ReferenceMeasurement {
                            index: 1,
                            algorithm: TcgAlgorithm::Sm3,
                            reference: attestation_report_v2.tee_info.rtmr1.to_vec(),
                        },
                        ReferenceMeasurement {
                            index: 2,
                            algorithm: TcgAlgorithm::Sm3,
                            reference: attestation_report_v2.tee_info.rtmr2.to_vec(),
                        },
                        ReferenceMeasurement {
                            index: 3,
                            algorithm: TcgAlgorithm::Sm3,
                            reference: attestation_report_v2.tee_info.rtmr3.to_vec(),
                        },
                        ReferenceMeasurement {
                            index: 4,
                            algorithm: TcgAlgorithm::Sm3,
                            reference: attestation_report_v2.tee_info.rtmr4.to_vec(),
                        },
                    ];

                    ccel.replay_and_match(compare_obj)?;
                    info!("EventLog integrity check succeeded.");

                    claims.as_object_mut().expect("Must be an object").insert(
                        "uefi_event_logs".to_string(),
                        serde_json::to_value(ccel.clone().log)?,
                    );
                }
                Ok(vec![(claims, "cpu".to_string())])
            }
        }
    }
}

async fn try_load_hskcek_offline(chip_id: &str) -> Option<Vec<u8>> {
    let hsk_cek_local_path = format!("{DEFAULT_CSV_CERT_DIR}/hsk_cek/{chip_id}/hsk_cek.cert");
    let hsk_cek_local_path = Path::new(&hsk_cek_local_path);

    fs::read(hsk_cek_local_path).await.ok()
}

async fn download_hskcek_from_kds(chip_id: &str) -> Result<Vec<u8>> {
    let kds_url: String = format!("https://cert.hygon.cn/hsk_cek?snumber={}", chip_id);

    debug!(url = kds_url, "Get HSK CEK from KDS");
    let hsk_cek_rsp: ReqwestResponse = get(kds_url)
        .await
        .context("Unable to send request for HSK_CEK")?;
    match hsk_cek_rsp.status() {
        StatusCode::OK => {
            let hsk_cek_bytes: Vec<u8> = hsk_cek_rsp
                .bytes()
                .await
                .context("Unable to parse HSK_CEK")?
                .to_vec();
            Ok(hsk_cek_bytes)
        }
        status => Err(anyhow!("Unable to fetch HSK_CEK from URL: {status:?}")),
    }
}

fn verify_report_signature(
    attestation_report: &AttestationReport,
    hsk: ca::Certificate,
    cek: csv_rs::certs::csv::Certificate,
    pek: csv_rs::certs::csv::Certificate,
) -> Result<(), CsvError> {
    // Verify certificate chain
    let hrk = ca::Certificate::decode(&mut &HRK[..], ())?;
    (&hrk, &hrk)
        .verify()
        .map_err(|err| CsvError::HRKSignatureVerification(err.to_string()))?;
    (&hrk, &hsk)
        .verify()
        .map_err(|err| CsvError::HSKSignatureValidation(err.to_string()))?;
    (&hsk, &cek)
        .verify()
        .map_err(|err| CsvError::CEKSignatureValidation(err.to_string()))?;
    (&cek, &pek)
        .verify()
        .map_err(|err| CsvError::PEKSignatureValidation(err.to_string()))?;

    // Verify the TEE Hardware signature.

    (&pek, &attestation_report.tee_info())
        .verify()
        .map_err(|err| CsvError::AttestationReportSignatureValidation(err.to_string()))?;

    Ok(()).map_err(|err| CsvError::VerifyReportSignature(err.to_string()))
}

#[cfg(test)]
mod tests {
    use crate::{csv::CsvVerifier, InitDataHash, ReportData, Verifier};

    #[tokio::test]
    async fn test_verify_csv_evidence() {
        let csv_evidence = tokio::fs::read("test_data/csv_evidence.json")
            .await
            .unwrap();
        let csv_evidence = serde_json::from_slice(&csv_evidence).unwrap();
        let csv_verifier = CsvVerifier::default();

        csv_verifier
            .evaluate(
                csv_evidence,
                &ReportData::NotProvided,
                &InitDataHash::NotProvided,
            )
            .await
            .expect("CSV Verifier should evaluate successfully");
    }
}
