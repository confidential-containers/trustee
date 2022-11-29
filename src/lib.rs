extern crate serde;

#[macro_use]
extern crate log;

extern crate strum;

#[macro_use]
extern crate strum_macros;

pub mod config;
pub mod policy_engine;
pub mod rvps;
pub mod types;
pub mod verifier;

use anyhow::{anyhow, Context, Result};
use config::Config;
use policy_engine::{PolicyEngine, PolicyEngineType};
use rvps::RVPSAPI;
use std::collections::HashMap;
use std::fs;
use std::str::FromStr;
use types::{Attestation, AttestationResults, TEE};

#[allow(dead_code)]
pub struct AttestationService {
    config: Config,
    policy_engine: Box<dyn PolicyEngine + Send + Sync>,
    rvps: rvps::Core,
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

        let rvps_store = config.rvps_store_type.to_store()?;
        let rvps = rvps::Core::new(rvps_store);

        Ok(Self {
            config,
            policy_engine,
            rvps,
        })
    }

    /// Evaluate Attestation Evidence.
    pub async fn evaluate(
        &self,
        tee: &str,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults> {
        let attestation = serde_json::from_str::<Attestation>(attestation)
            .context("Failed to deserialize Attestation")?;
        let verifier = TEE::from_str(tee)?.to_verifier()?;

        let claims_from_tee_evidence =
            match verifier.evaluate(nonce.to_string(), &attestation).await {
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

        let tcb = serde_json::to_string(&claims_from_tee_evidence)?;
        let reference_data_map = self
            .get_reference_data(&tcb)
            .map_err(|e| anyhow!("Generate reference data failed{:?}", e))?;

        let (result, policy_engine_output) = self
            .policy_engine
            .evaluate(reference_data_map, tcb.clone())?;

        let attestation_results = AttestationResults::new(
            tee.to_string(),
            result,
            None,
            Some(policy_engine_output),
            Some(tcb),
        );
        debug!("Attestation Results: {:?}", &attestation_results);

        Ok(attestation_results)
    }

    fn get_reference_data(&self, tcb_claims: &str) -> Result<HashMap<String, Vec<String>>> {
        let mut data = HashMap::new();
        let tcb_claims_map: HashMap<String, Vec<String>> = serde_json::from_str(tcb_claims)?;
        for key in tcb_claims_map.keys() {
            data.insert(
                key.to_string(),
                self.rvps
                    .get_digests(key)?
                    .unwrap_or_default()
                    .hash_values
                    .clone(),
            );
        }
        Ok(data)
    }
}
