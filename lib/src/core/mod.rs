use anyhow::{Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use crate::*;

pub mod proxy;
pub mod verifier;
use verifier::Verifier;
use verifier::*;

#[macro_export]
macro_rules! default_policy {
    () => {
        "policy.rego"
    };
}

#[macro_export]
macro_rules! default_reference_data {
    () => {
        "reference_data.json"
    };
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Evidence {
    pub nonce: String,
    pub tee: String,
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: String,
    #[serde(rename = "tee-evidence")]
    pub tee_evidence: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationResults {
    pub tee: String,
    pub result: String,
    pub policy_info: String,
    pub tcb: String,
}

impl TEE {
    fn to_verifier(&self) -> Result<Box<dyn Verifier + Send + Sync>> {
        match self {
            TEE::SGX => Ok(Box::new(sgx::Sgx::default()) as Box<dyn Verifier + Send + Sync>),
            TEE::TDX => Ok(Box::new(tdx::Tdx::default()) as Box<dyn Verifier + Send + Sync>),
            TEE::SAMPLE => {
                Ok(Box::new(sample::Sample::default()) as Box<dyn Verifier + Send + Sync>)
            }
            _ => Err(anyhow!("TEE is not supported!")),
        }
    }
}

#[derive(Debug, Default)]
pub struct Attestation {}

impl Attestation {
    pub async fn evaluate(
        &self,
        evidence: &String,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<String> {
        let evidence =
            serde_json::from_str::<Evidence>(evidence).context("Deserialize Evidence failed.")?;
        let verifier = TEE::from_str(&evidence.tee)?.to_verifier()?;
        let results = verifier.evaluate(&evidence, policy, reference_data).await?;
        let results = serde_json::to_string(&results)?;
        debug!("Attestation Results: {}", &results);
        Ok(results)
    }

    pub fn policy(&self, tee: TEE) -> Result<String> {
        tee.to_verifier()?.default_policy()
    }

    pub fn reference_data(&self, tee: TEE) -> Result<String> {
        tee.to_verifier()?.default_reference_data()
    }
}
