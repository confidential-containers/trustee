use crate::verifier::*;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub type TeeEvidenceParsedClaim = serde_json::Value;

/// The supported TEE types:
/// - TDX: TDX TEE.
/// - SGX: SGX TEE.
/// - SEVSNP: SEV-SNP TEE.
/// - SAMPLE: A dummy TEE that used to test/demo the attestation service functionalities.
#[derive(Debug, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum TEE {
    TDX,
    SGX,
    SEVSNP,
    SAMPLE,
}

impl TEE {
    #[allow(dead_code)]
    pub fn to_verifier(&self) -> Result<Box<dyn Verifier + Send + Sync>> {
        match self {
            TEE::SAMPLE => {
                Ok(Box::new(sample::Sample::default()) as Box<dyn Verifier + Send + Sync>)
            }
            _ => Err(anyhow!("TEE is not supported!")),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: String,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResults {
    tee: String,
    allow: bool,
    output: ResultOutput,
    tcb: Option<String>,
}

impl AttestationResults {
    pub fn new(
        tee: String,
        allow: bool,
        verifier_output: Option<String>,
        policy_engine_output: Option<String>,
        tcb: Option<String>,
    ) -> Self {
        Self {
            tee,
            allow,
            output: ResultOutput {
                verifier_output,
                policy_engine_output,
            },
            tcb,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ResultOutput {
    pub verifier_output: Option<String>,
    pub policy_engine_output: Option<String>,
}
