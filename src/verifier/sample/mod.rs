use anyhow::{anyhow, Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64;
use serde_json::json;
use sha2::{Digest, Sha384};

#[derive(Serialize, Deserialize, Debug)]
struct SampleTeeEvidence {
    svn: String,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_str::<SampleTeeEvidence>(&attestation.tee_evidence)
            .context("Deserialize Quote failed.")?;

        let mut hasher = Sha384::new();
        hasher.update(&nonce);
        hasher.update(&attestation.tee_pubkey.k_mod);
        hasher.update(&attestation.tee_pubkey.k_exp);
        let reference_report_data = base64::encode(hasher.finalize());

        verify_tee_evidence(reference_report_data, &tee_evidence)
            .await
            .context("Evidence's identity verification error.")?;

        debug!("TEE-Evidence<sample>: {:?}", tee_evidence);

        parse_tee_evidence(&tee_evidence)
    }
}

async fn verify_tee_evidence(
    reference_report_data: String,
    tee_evidence: &SampleTeeEvidence,
) -> Result<()> {
    // Verify the TEE Hardware signature. (Null for sample TEE)

    // Emulate the report data.
    if tee_evidence.report_data != reference_report_data {
        return Err(anyhow!("Report data verification failed!"));
    }

    Ok(())
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn parse_tee_evidence(quote: &SampleTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": quote.svn
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}
