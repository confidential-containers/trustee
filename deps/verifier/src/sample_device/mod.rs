// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use log::debug;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use serde_json::json;

#[derive(Serialize, Deserialize, Debug)]
struct SampleDeviceEvidence {
    svn: String,

    #[serde(default = "String::default")]
    report_data: String,
}

#[derive(Debug, Default)]
pub struct SampleDeviceVerifier {}

#[async_trait]
impl Verifier for SampleDeviceVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_slice::<SampleDeviceEvidence>(evidence)
            .context("Deserialize Quote failed.")?;

        verify_tee_evidence(expected_report_data, expected_init_data_hash, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("TEE-Evidence<sample_device>: {:?}", tee_evidence);

        parse_tee_evidence(&tee_evidence)
    }
}

async fn verify_tee_evidence(
    expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
    evidence: &SampleDeviceEvidence,
) -> Result<()> {
    // Verify the TEE Hardware signature. (Null for sample TEE)

    // Emulate the report data.
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let ev_report_data = base64::engine::general_purpose::STANDARD
            .decode(&evidence.report_data)
            .context("base64 decode report data for sample evidence")?;
        if *expected_report_data != ev_report_data {
            bail!("REPORT_DATA is different from that in Sample Quote");
        }
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleDeviceEvidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": quote.svn,
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
