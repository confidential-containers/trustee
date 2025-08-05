use log::{debug, warn};
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
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tee_evidence = serde_json::from_value::<SampleTeeEvidence>(evidence)
            .context("Deserialize Quote failed.")?;

        verify_tee_evidence(expected_report_data, expected_init_data_hash, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("TEE-Evidence<sample>: {:?}", tee_evidence);

        let claims = parse_tee_evidence(&tee_evidence)?;
        Ok((claims, "cpu".to_string()))
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

    if let InitDataHash::Value(_) = expected_init_data_hash {
        warn!("Sample does not support init data hash mechanism. skip.");
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": quote.svn,
        "report_data": quote.report_data,

        // Generally TCB claims should originate from the attester.
        "launch_digest": "abcde",

        // TCB Claims can be any type supported by serde_json
        "platform_version": {
            "major": 1,
            "minor": 4,
        },

        // An example of a claim representing the platform configuration.
        // The sample platform is in a sense only for debugging.
        // This claim will always be set to false and is only for testing.
        "debug": false,
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
