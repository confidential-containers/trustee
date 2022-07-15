use anyhow::{Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use crate::core::policy_engine::opa;
use crate::default_policy;
use crate::*;

pub mod policy_engine;
pub mod proxy;
pub mod verifier;
use serde_json::Value;
use std::collections::HashMap;
use verifier::Verifier;
use verifier::*;

#[macro_export]
macro_rules! default_policy {
    () => {
        "./policy_engine/default_policy.rego"
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
    pub allow: bool,
    pub verifier_output: String,
    pub policy_engine_output: String,
    pub tcb: String,
}

pub type TeeEvidenceParsedClaim = serde_json::Value;

impl TEE {
    fn to_verifier(&self) -> Result<Box<dyn Verifier + Send + Sync>> {
        match self {
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
        evidence: &str,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<String> {
        let evidence =
            serde_json::from_str::<Evidence>(evidence).context("Deserialize Evidence failed.")?;
        let verifier = TEE::from_str(&evidence.tee)?.to_verifier()?;

        let claims_from_tee_evidence = match verifier.evaluate(&evidence).await {
            Ok(claims) => claims,
            Err(e) => {
                let attestation_results = serde_json::to_string(&AttestationResults {
                    tee: evidence.tee.clone(),
                    allow: false,
                    verifier_output: format!("Verifier evaluate failed: {:?}", e),
                    policy_engine_output: String::default(),
                    tcb: String::default(),
                })?;
                return Ok(attestation_results);
            }
        };

        let opa_input_data = serde_json::to_string(&claims_from_tee_evidence)?;

        let opa_policy = policy.unwrap_or_else(|| std::include_str!(default_policy!()).to_string());
        let opa_reference_data = match reference_data {
            Some(data) => data,
            None => {
                let mut data: HashMap<String, Vec<String>> = HashMap::new();
                let claims_map: HashMap<String, serde_json::Value> =
                    serde_json::from_value(claims_from_tee_evidence.clone())?;
                for key in claims_map.keys() {
                    data.insert(key.to_string(), Vec::new());
                }
                serde_json::json!({ "reference": data }).to_string()
            }
        };
        // TODO: Update the reference data with RVPS.

        let opa_output = opa::evaluate(opa_policy, opa_reference_data, opa_input_data)?;
        let v_opa_output: Value = serde_json::from_str(&opa_output)?;

        let attestation_results = AttestationResults {
            tee: evidence.tee.clone(),
            allow: v_opa_output["allow"].as_bool().unwrap_or(false),
            verifier_output: String::default(),
            policy_engine_output: opa_output,
            tcb: serde_json::to_string(&claims_from_tee_evidence)?,
        };

        let results = serde_json::to_string(&attestation_results)?;

        debug!("Attestation Results: {:?}", &attestation_results);
        Ok(results)
    }

    pub fn default_policy(&self) -> Result<String> {
        Ok(std::include_str!(default_policy!()).to_string())
    }
}
