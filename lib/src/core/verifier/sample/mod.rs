use anyhow::{anyhow, Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use crate::core::verifier::policy::opa;
use crate::default_policy;
use crate::default_reference_data;
use async_trait::async_trait;
use base64;
use serde_json::{json, Value};
use sha2::{Digest, Sha384};

#[derive(Serialize, Deserialize, Debug)]
struct Ehd {
    nonce: String,
    public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Tcb {
    is_debuggable: bool,
    // CPU Security Version Number
    cpusvn: u64,
    // TEE Security Version Number
    svn: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct Quote {
    is_debuggable: bool,
    cpusvn: u64,
    svn: u64,
    report_data: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct PolicyInfo {
    // Policy Engine's policy file.
    policy_name: String,
    // Policy Engine's policy file's hash value.
    policy_hash: String,
    // Policy Engine's evaluation info.
    info: String,
}

#[derive(Debug, Default)]
pub struct Sample {}

#[async_trait]
impl Verifier for Sample {
    async fn evaluate(
        &self,
        evidence: &Evidence,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<AttestationResults> {
        // Use the default policy/reference_data if the input is None.
        let policy = policy.unwrap_or_else(|| std::include_str!(default_policy!()).to_string());
        let reference_data = reference_data
            .unwrap_or_else(|| std::include_str!(default_reference_data!()).to_string());

        verify(evidence)
            .await
            .context("Evidence's identity verification error.")?;

        let tcb = tcb_status(&evidence.tee_evidence)?;
        let input = json!({
            "cpusvn": tcb.cpusvn,
            "svn": tcb.svn
        })
        .to_string();
        let evaluation = opa::evaluate(policy, reference_data, input)?;
        let v: Value = serde_json::from_str(&evaluation)?;
        let info = PolicyInfo {
            policy_name: default_policy!().to_string(),
            policy_hash: "".to_string(),
            info: evaluation,
        };
        Ok(AttestationResults {
            tee: "sample".to_string(),
            result: v["allow"].to_string(),
            policy_info: serde_json::to_string(&info)?,
            tcb: serde_json::to_string(&tcb)?,
        })
    }

    // Get the default OPA policy.
    fn default_policy(&self) -> Result<String> {
        Ok(std::include_str!(default_policy!()).to_string())
    }

    // Get the default OPA reference data.
    fn default_reference_data(&self) -> Result<String> {
        Ok(std::include_str!(default_reference_data!()).to_string())
    }
}

// Demo to fetch the TCB status from the quote
fn tcb_status(quote: &str) -> Result<Tcb> {
    debug!("Quote<sample>: {}", &quote);
    let q = serde_json::from_str::<Quote>(quote).context("Deserialize Quote failed.")?;
    Ok(Tcb {
        is_debuggable: false,
        cpusvn: q.cpusvn,
        svn: q.svn,
    })
}

async fn verify(evidence: &Evidence) -> Result<()> {
    // Emulate the quote identity verificaition.
    let quote = serde_json::from_str::<Quote>(&evidence.tee_evidence)
        .context("Deserialize quote failed.")?;
    let mut hasher = Sha384::new();
    hasher.update(&evidence.nonce);
    hasher.update(&evidence.tee_pubkey);
    let hash = hasher.finalize();
    if quote.report_data != base64::encode(hash) {
        return Err(anyhow!("Report data verification failed!"));
    }
    Ok(())
}
