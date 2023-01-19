//! Attestation Service
//!
//! # Features
//! - `rvps-proxy`: The AS will connect a remote RVPS.
//! - `rvps-server`: The AS will integrate RVPS functionalities itself.

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
pub use kbs_types::{Attestation, Tee};
use policy_engine::PolicyEngine;
use rvps::{Message, RVPSAPI};
use std::collections::HashMap;

use types::AttestationResults;

#[cfg(any(feature = "rvps-proxy", feature = "rvps-server"))]
use std::{fs, str::FromStr};

#[cfg(any(feature = "rvps-proxy", feature = "rvps-server"))]
use policy_engine::PolicyEngineType;

pub struct AttestationService {
    _config: Config,
    policy_engine: Box<dyn PolicyEngine + Send + Sync>,
    rvps: Box<dyn RVPSAPI + Send + Sync>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    #[cfg(feature = "rvps-server")]
    pub fn new() -> Result<Self> {
        let _config = Config::default();
        if !_config.work_dir.as_path().exists() {
            fs::create_dir_all(&_config.work_dir)
                .map_err(|e| anyhow!("Create AS work dir failed: {:?}", e))?;
        }

        let policy_engine = PolicyEngineType::from_str(&_config.policy_engine)
            .map_err(|_| anyhow!("Policy Engine {} is not supported", &_config.policy_engine))?
            .to_policy_engine(_config.work_dir.as_path())?;

        let rvps_store = _config.rvps_store_type.to_store()?;
        let rvps = Box::new(rvps::Core::new(rvps_store));

        Ok(Self {
            _config,
            policy_engine,
            rvps,
        })
    }

    /// Create a new Attestation Service, and connect to a remote rvps.
    #[cfg(feature = "rvps-proxy")]
    pub async fn new_with_rvps_proxy(rvps_addr: &str) -> Result<Self> {
        let _config = Config::default();
        if !_config.work_dir.as_path().exists() {
            fs::create_dir_all(&_config.work_dir)
                .map_err(|e| anyhow!("Create AS work dir failed: {:?}", e))?;
        }

        let policy_engine = PolicyEngineType::from_str(&_config.policy_engine)
            .map_err(|_| anyhow!("Policy Engine {} is not supported", &_config.policy_engine))?
            .to_policy_engine(_config.work_dir.as_path())?;

        let rvps = Box::new(rvps::Agent::new(rvps_addr).await?);

        Ok(Self {
            _config,
            policy_engine,
            rvps,
        })
    }

    /// Evaluate Attestation Evidence.
    pub async fn evaluate(
        &self,
        tee: Tee,
        nonce: &str,
        attestation: &str,
    ) -> Result<AttestationResults> {
        let attestation = serde_json::from_str::<Attestation>(attestation)
            .context("Failed to deserialize Attestation")?;
        let verifier = crate::verifier::to_verifier(&tee)?;

        let claims_from_tee_evidence =
            match verifier.evaluate(nonce.to_string(), &attestation).await {
                Ok(claims) => claims,
                Err(e) => {
                    return Ok(AttestationResults::new(
                        tee,
                        false,
                        Some(format!("Verifier evaluate failed: {e:?}")),
                        None,
                        None,
                    ));
                }
            };

        let tcb = serde_json::to_string(&claims_from_tee_evidence)?;
        let reference_data_map = self
            .get_reference_data(&tcb)
            .await
            .map_err(|e| anyhow!("Generate reference data failed{:?}", e))?;

        let (result, policy_engine_output) = self
            .policy_engine
            .evaluate(reference_data_map, tcb.clone())?;

        let attestation_results =
            AttestationResults::new(tee, result, None, Some(policy_engine_output), Some(tcb));
        debug!("Attestation Results: {:?}", &attestation_results);

        Ok(attestation_results)
    }

    async fn get_reference_data(&self, tcb_claims: &str) -> Result<HashMap<String, Vec<String>>> {
        let mut data = HashMap::new();
        let tcb_claims_map: HashMap<String, String> = serde_json::from_str(tcb_claims)?;
        for key in tcb_claims_map.keys() {
            data.insert(
                key.to_string(),
                self.rvps
                    .get_digests(key)
                    .await?
                    .unwrap_or_default()
                    .hash_values
                    .clone(),
            );
        }
        Ok(data)
    }

    /// Registry a new reference value
    pub async fn registry_reference_value(&mut self, message: Message) -> Result<()> {
        self.rvps.verify_and_extract(message).await
    }
}
