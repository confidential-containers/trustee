use anyhow::{Context, Result};
use log::debug;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use serde_json::json;

#[derive(Serialize, Deserialize, Debug)]
struct SampleTeeEvidence {
    svn: String,

    #[serde(default = "String::default")]
    report_data: String,

    #[serde(default = "String::default")]
    init_data: String,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_slice::<SampleTeeEvidence>(evidence)
            .context("Deserialize Quote failed.")?;

        verify_tee_evidence(expected_report_data, expected_init_data_hash, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("TEE-Evidence<sample>: {:?}", tee_evidence);

        parse_tee_evidence(&tee_evidence)
    }
}

async fn verify_tee_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: &SampleTeeEvidence,
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

    // Emulate the init data hash.
    if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
        debug!("Check the binding of init_data_digest.");
        let ev_init_data_hash = base64::engine::general_purpose::STANDARD
            .decode(&evidence.init_data)
            .context("base64 decode init data hash for sample evidence")?;
        if *expected_init_data_hash != ev_init_data_hash {
            bail!("INIT DATA HASH is different from that in Sample Quote");
        }
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": quote.svn,
        "report_data": quote.report_data,
        "init_data": quote.init_data,
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
