extern crate serde;

#[macro_use]
extern crate log;

extern crate strum;

#[macro_use]
extern crate strum_macros;

pub mod policy_engine;
pub mod types;
pub mod verifier;

use anyhow::{Context, Result};
use policy_engine::opa;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use types::{AttestationResults, Evidence, TEE};

#[macro_export]
macro_rules! default_policy {
    () => {
        "../default_policy.rego"
    };
}

#[derive(Debug, Default)]
pub struct AttestationService {
    policy: String,
    reference_data: String,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub fn new() -> Result<Self> {
        let policy = std::include_str!(default_policy!()).to_string();

        let data: HashMap<String, Vec<String>> = HashMap::new();
        //TODO: Reference data actually should be generated from RVPS storage when `evaluate` is called.
        let reference_data = serde_json::json!({ "reference": data }).to_string();

        Ok(Self {
            policy,
            reference_data,
        })
    }

    /// Get current policy.
    pub fn policy(&self) -> String {
        self.policy.clone()
    }

    /// Set customize policy.
    pub fn set_policy(&mut self, policy: String) {
        self.policy = policy;
    }

    /// Evaluate Attestation Evicende.
    pub async fn evaluate(
        &self,
        tee: &str,
        nonce: &str,
        evidence: &str,
    ) -> Result<AttestationResults> {
        let evidence =
            serde_json::from_str::<Evidence>(evidence).context("Deserialize Evidence failed.")?;
        let verifier = TEE::from_str(tee)?.to_verifier()?;

        let claims_from_tee_evidence = match verifier.evaluate(nonce.to_string(), &evidence).await {
            Ok(claims) => claims,
            Err(e) => {
                return Ok(AttestationResults::new(
                    tee.to_string(),
                    false,
                    Some(format!("Verifier evaluate failed: {:?}", e)),
                    None,
                    None,
                ));
            }
        };

        let opa_output = opa::evaluate(
            self.policy.clone(),
            self.reference_data.clone(),
            serde_json::to_string(&claims_from_tee_evidence)?,
        )?;
        let v_opa_output: Value = serde_json::from_str(&opa_output)?;

        let attestation_results = AttestationResults::new(
            tee.to_string(),
            v_opa_output["allow"].as_bool().unwrap_or(false),
            None,
            Some(opa_output),
            Some(serde_json::to_string(&claims_from_tee_evidence)?),
        );
        debug!("Attestation Results: {:?}", &attestation_results);

        Ok(attestation_results)
    }
}
