use anyhow::{anyhow, Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64;
use serde_json::json;
use sha2::{Digest, Sha384};

#[derive(Serialize, Deserialize, Debug)]
struct Quote {
    is_debuggable: bool,
    // CPU Security Version Number
    cpusvn: u64,
    // TEE Security Version Number
    svn: u64,
    report_data: String,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(&self, evidence: &Evidence) -> Result<TeeEvidenceParsedClaim> {
        verify(evidence)
            .await
            .context("Evidence's identity verification error.")?;

        let quote = serde_json::from_str::<Quote>(&evidence.tee_evidence)
            .context("Deserialize Quote failed.")?;
        debug!("Quote<sample>: {:?}", &quote);

        tcb_status(&quote)
    }
}

// Dump the TCB status from the quote.
// Example: CPU SVN, RTMR, etc.
fn tcb_status(quote: &Quote) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "cpusvn": quote.cpusvn,
        "svn": quote.svn
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}

#[derive(Serialize, Deserialize, Debug)]
struct Ehd {
    nonce: String,
    public_key: String,
}

async fn verify(evidence: &Evidence) -> Result<()> {
    // Emulate the EHD (report data).
    let quote = serde_json::from_str::<Quote>(&evidence.tee_evidence)
        .context("Deserialize quote failed.")?;
    let mut hasher = Sha384::new();
    hasher.update(&evidence.nonce);
    hasher.update(&evidence.tee_pubkey);
    let hash = hasher.finalize();
    if quote.report_data != base64::encode(hash) {
        return Err(anyhow!("Report data verification failed!"));
    }

    // Verify the TEE Hardware signature. (Null for sample TEE)

    Ok(())
}
