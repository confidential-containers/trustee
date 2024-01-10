//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.
//! - `rvps-builtin`: The AS will integrate RVPS functionalities itself.

pub mod config;
pub mod policy_engine;
mod rvps;
mod token;
mod utils;

use crate::token::AttestationTokenBroker;

use anyhow::{anyhow, Context, Result};
use config::Config;
pub use kbs_types::{Attestation, Tee};
use log::debug;
use policy_engine::{PolicyEngine, PolicyEngineType, SetPolicyInput};
use rvps::RvpsApi;
use serde_json::{json, Value};
use serde_variant::to_variant_name;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{collections::HashMap, str::FromStr};
use strum::{AsRefStr, EnumString};
use tokio::fs;
use verifier::{InitDataHash, ReportData};

use crate::utils::flatten_claims;

/// Hash algorithms used to calculate runtime/init data binding
#[derive(EnumString, AsRefStr)]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    Sha256,

    #[strum(ascii_case_insensitive)]
    Sha384,

    #[strum(ascii_case_insensitive)]
    Sha512,
}

impl HashAlgorithm {
    fn accumulate_hash(&self, materials: Vec<u8>) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha384 => {
                let mut hasher = Sha384::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(materials);
                hasher.finalize().to_vec()
            }
        }
    }
}

/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
pub enum Data {
    /// This will be used as the expected runtime/init data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime/Init data in a JSON map. CoCoAS will rearrange each layer of the
    /// data JSON object in dictionary order by key, then serialize and output
    /// it into a compact string, and perform hash calculation on the whole
    /// to check against the one inside evidence.
    Structured(Value),
}

pub struct AttestationService {
    _config: Config,
    policy_engine: Box<dyn PolicyEngine + Send + Sync>,
    rvps: Box<dyn RvpsApi + Send + Sync>,
    token_broker: Box<dyn AttestationTokenBroker + Send + Sync>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub async fn new(config: Config) -> Result<Self> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .context("Create AS work dir failed: {:?}")?;
        }

        let policy_engine = PolicyEngineType::from_str(&config.policy_engine)
            .map_err(|_| anyhow!("Policy Engine {} is not supported", &config.policy_engine))?
            .to_policy_engine(config.work_dir.as_path())?;

        let rvps = config
            .rvps_config
            .to_rvps()
            .await
            .context("create rvps failed.")?;

        let token_broker = config
            .attestation_token_broker
            .to_token_broker(config.attestation_token_config.clone())?;

        Ok(Self {
            _config: config,
            policy_engine,
            rvps,
            token_broker,
        })
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()> {
        self.policy_engine
            .set_policy(input)
            .await
            .map_err(|e| anyhow!("Cannot Set Policy: {:?}", e))
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key. Input parameters:
    /// - `evidence`: TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    /// are in `verifier` crate.
    /// - `tee`: concrete TEE type
    /// - `runtime_data`: These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    /// - `init_data`: These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    /// - `hash_algorithm`: The hash algorithm that is used to calculate the digest of `runtime_data` and
    /// `init_data`.
    /// - `policy_ids`: The policy ids that used to check this evidence. Any check fails against a policy will
    /// not cause this function to return error. The result check against every policy will be included inside
    /// the finally Token returned by CoCo-AS.
    #[allow(clippy::too_many_arguments)]
    pub async fn evaluate(
        &self,
        evidence: Vec<u8>,
        tee: Tee,
        runtime_data: Option<Data>,
        runtime_data_hash_algorithm: HashAlgorithm,
        init_data: Option<Data>,
        init_data_hash_algorithm: HashAlgorithm,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;

        let (report_data, runtime_data_claims) =
            parse_data(runtime_data, &runtime_data_hash_algorithm).context("parse runtime data")?;

        let report_data = match &report_data {
            Some(data) => ReportData::Value(data),
            None => ReportData::NotProvided,
        };

        let (init_data, init_data_claims) =
            parse_data(init_data, &init_data_hash_algorithm).context("parse init data")?;

        let init_data_hash = match &init_data {
            Some(data) => InitDataHash::Value(data),
            None => InitDataHash::NotProvided,
        };

        let claims_from_tee_evidence = verifier
            .evaluate(&evidence, &report_data, &init_data_hash)
            .await
            .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;

        let flattened_claims = flatten_claims(tee, &claims_from_tee_evidence)?;

        let tcb_json = serde_json::to_string(&flattened_claims)?;

        let reference_data_map = self
            .get_reference_data(flattened_claims.keys())
            .await
            .map_err(|e| anyhow!("Generate reference data failed: {:?}", e))?;

        let evaluation_report = self
            .policy_engine
            .evaluate(reference_data_map.clone(), tcb_json, policy_ids.clone())
            .await
            .map_err(|e| anyhow!("Policy Engine evaluation failed: {e}"))?;

        let policies: Vec<_> = evaluation_report
            .into_iter()
            .map(|(k, v)| {
                json!({
                    "policy-id": k,
                    "policy-hash": v.0,
                    "evaluation-result": v.1,
                })
            })
            .collect();

        let reference_data_map: HashMap<String, Vec<String>> = reference_data_map
            .into_iter()
            .filter(|it| !it.1.is_empty())
            .collect();

        let token_claims = json!({
            "tee": to_variant_name(&tee)?,
            "evaluation-reports": policies,
            "tcb-status": flattened_claims,
            "reference-data": reference_data_map,
            "customized_claims": {
                "init_data": init_data_claims,
                "runtime_data": runtime_data_claims,
            },
        });

        let attestation_results_token = self.token_broker.issue(token_claims)?;

        Ok(attestation_results_token)
    }

    async fn get_reference_data<'a, I>(&self, tcb_claims: I) -> Result<HashMap<String, Vec<String>>>
    where
        I: Iterator<Item = &'a String>,
    {
        let mut data = HashMap::new();
        for key in tcb_claims {
            let reference_value = self.rvps.get_digests(key).await?;
            if !reference_value.is_empty() {
                debug!("Successfully get reference values of {key} from RVPS.");
            }
            data.insert(key.to_string(), reference_value);
        }
        Ok(data)
    }

    /// Registry a new reference value
    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps.verify_and_extract(message).await
    }
}

/// Get the expected init/runtime data and potential claims due to the given input
/// and the hash algorithm
fn parse_data(
    data: Option<Data>,
    hash_algorithm: &HashAlgorithm,
) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            Data::Raw(raw) => Ok((Some(raw), Value::Null)),
            Data::Structured(structured) => {
                // by default serde_json will enforence the alphabet order for keys
                let hash_materials =
                    serde_json::to_vec(&structured).context("parse JSON structured data")?;
                let digest = hash_algorithm.accumulate_hash(hash_materials);
                Ok((Some(digest), structured))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use serde_json::{json, Value};

    use crate::{Data, HashAlgorithm};

    #[rstest]
    #[case(Some(Data::Raw(b"aaaaa".to_vec())), Some(b"aaaaa".to_vec()), HashAlgorithm::Sha384, Value::Null)]
    #[case(None, None, HashAlgorithm::Sha384, Value::Null)]
    #[case(Some(Data::Structured(json!({"b": 1, "a": "test", "c": {"d": "e"}}))), Some(hex::decode(b"e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3").unwrap()), HashAlgorithm::Sha384, json!({"b": 1, "a": "test", "c": {"d": "e"}}))]
    fn parse_data_json_binding(
        #[case] input: Option<Data>,
        #[case] expected_data: Option<Vec<u8>>,
        #[case] hash_algorithm: HashAlgorithm,
        #[case] expected_claims: Value,
    ) {
        let (data, data_claims) = crate::parse_data(input, &hash_algorithm).expect("parse failed");
        assert_eq!(data, expected_data);
        assert_json_eq!(data_claims, expected_claims);
    }
}
