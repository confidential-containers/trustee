extern crate serde;

#[macro_use]
extern crate log;

extern crate strum;

#[macro_use]
extern crate strum_macros;

pub mod config;
pub mod policy_engine;
pub mod types;
pub mod verifier;

use anyhow::{anyhow, Context, Result};
use config::Config;
use policy_engine::{PolicyEngine, PolicyEngineType};
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;
use types::{AttestationResults, Evidence, TEE};

#[allow(dead_code)]
pub struct AttestationService {
    config: Config,
    policy_engine: Box<dyn PolicyEngine + Send + Sync>,
    reference_values: String,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub fn new() -> Result<Self> {
        let config = Config::default();
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .map_err(|e| anyhow!("Create AS work dir failed: {:?}", e))?;
        }

        let policy_engine = PolicyEngineType::from_str(&config.policy_engine)
            .map_err(|_| anyhow!("Policy Engine {} is not supported", &config.policy_engine))?
            .to_policy_engine(config.work_dir.as_path())?;

        let data: HashMap<String, Vec<String>> = HashMap::new();
        //TODO: Reference values actually should be generated from RVPS storage when `evaluate` is called.
        let reference_values = serde_json::json!({ "reference": data }).to_string();

        Ok(Self {
            config,
            policy_engine,
            reference_values,
        })
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

        let (result, policy_engine_output) = self.policy_engine.evaluate(
            self.reference_values.clone(),
            serde_json::to_string(&claims_from_tee_evidence)?,
        )?;

        let attestation_results = AttestationResults::new(
            tee.to_string(),
            result,
            None,
            Some(policy_engine_output),
            Some(serde_json::to_string(&claims_from_tee_evidence)?),
        );
        debug!("Attestation Results: {:?}", &attestation_results);

        Ok(attestation_results)
    }
}
