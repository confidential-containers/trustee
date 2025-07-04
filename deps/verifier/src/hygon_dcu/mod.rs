// Copyright (c) 2025 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{bail, Result};
use async_trait::async_trait;
use csv_rs::api::dcu::{verify_reports, AttestationReport};
use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map};

use crate::{
    regularize_data, InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim,
    Verifier,
};

#[derive(Serialize, Deserialize)]
struct DcuEvidence {
    attestation_reports: Vec<AttestationReport>,
}

pub const HYGON_DCU_TEE_CLASS: &str = "dcu";

#[derive(Debug, Default)]
pub struct HygonDcuVerifier {}

#[async_trait]
impl Verifier for HygonDcuVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tee_evidence = serde_json::from_value::<DcuEvidence>(evidence)?;

        let expected_report_data = match expected_report_data {
            ReportData::Value(expected_report_data) => {
                let user_data_slice =
                    regularize_data(expected_report_data, 64, "REPORT_DATA", "Hygon DCU");
                let mut user_data = [0u8; 64];
                user_data.copy_from_slice(&user_data_slice[..64]);
                user_data
            }
            ReportData::NotProvided => bail!("DCU must check report data"),
        };

        verify_reports(&tee_evidence.attestation_reports, &expected_report_data).await?;

        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("DCU does not support init data hash mechanism. skip.");
        }

        let claims = parse_tee_evidence(tee_evidence.attestation_reports)?;
        Ok((claims, "dcu".to_string()))
    }
}

// Dump the DCU information from the report.
fn parse_tee_evidence(reports: Vec<AttestationReport>) -> Result<TeeEvidenceParsedClaim> {
    let mut claims = Map::new();
    for (index, report) in reports.into_iter().enumerate() {
        let key = index.to_string();
        let value = json!({
            "body": {
                "version": report.body.version,
                "chip_id": hex::encode(report.body.chip_id),
                "user_data": hex::encode(report.body.user_data),
                "measure": hex::encode(report.body.measure),
                "reserved": hex::encode(report.body.reserved),
                "sig_usage": format!("{:x}", report.body.sig_usage),
                "sig_algo": format!("{:x}", report.body.sig_algo),
            },
            "report_data": hex::encode(report.body.user_data),
        });
        claims.insert(key, value);
    }

    Ok(TeeEvidenceParsedClaim::Object(claims))
}
