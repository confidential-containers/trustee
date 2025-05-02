//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.

pub mod config;
pub mod policy_engine;
pub mod rvps;
pub mod token;

use crate::token::AttestationTokenBroker;

use anyhow::{anyhow, bail, Context, Result};
use config::Config;
pub use kbs_types::{Attestation, Tee};
use log::{debug, info};
use rvps::{RvpsApi, RvpsError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use strum::{AsRefStr, Display, EnumString};
use thiserror::Error;
use tokio::fs;
use verifier::{InitDataHash, ReportData, TeeEvidenceParsedClaim};

/// Hash algorithms used to calculate runtime/init data binding
#[derive(Debug, Display, EnumString, AsRefStr)]
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

pub type TeeEvidence = serde_json::Value;
pub type TeeClass = String;

/// GuestEvidence is the combined evidence from all the TEEs
/// that represent the guest.
#[derive(Serialize, Deserialize)]
pub struct GuestEvidence {
    primary_evidence: TeeEvidence,
    primary_tee_class: TeeClass,
    // The additional evidence is a map of Tee -> (TeeClass, TeeEvidence),
    // but we convert it to a string to avoid any inconsistencies
    // with serialization. The string in this struct is exactly
    // what is used to calculate the runtime data.
    additional_evidence: String,
}

/// Tee Claims are the output of the verifier plus some metadata
/// that identifies the TEE type and class.
#[derive(Debug)]
pub struct TeeClaims {
    tee: Tee,
    tee_class: TeeClass,
    claims: TeeEvidenceParsedClaim,
}

/// Runtime/Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Clone, Debug)]
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

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Create AS work dir failed: {0}")]
    CreateDir(#[source] std::io::Error),
    #[error("Policy Engine is not supported: {0}")]
    UnsupportedPolicy(#[source] strum::ParseError),
    #[error("Create rvps failed: {0}")]
    Rvps(#[source] RvpsError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub struct AttestationService {
    _config: Config,
    rvps: Box<dyn RvpsApi + Send + Sync>,
    token_broker: Box<dyn AttestationTokenBroker + Send + Sync>,
}

impl AttestationService {
    /// Create a new Attestation Service instance.
    pub async fn new(config: Config) -> Result<Self, ServiceError> {
        if !config.work_dir.as_path().exists() {
            fs::create_dir_all(&config.work_dir)
                .await
                .map_err(ServiceError::CreateDir)?;
        }

        let rvps = rvps::initialize_rvps_client(&config.rvps_config)
            .await
            .map_err(ServiceError::Rvps)?;

        let token_broker = config.attestation_token_broker.to_token_broker()?;

        Ok(Self {
            _config: config,
            rvps,
            token_broker,
        })
    }

    /// Set Attestation Verification Policy.
    pub async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()> {
        self.token_broker.set_policy(policy_id, policy).await?;
        Ok(())
    }

    /// Get Attestation Verification Policy List.
    /// The result is a `policy-id` -> `policy hash` map.
    pub async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.token_broker
            .list_policies()
            .await
            .context("Cannot List Policy")
    }

    /// Get a single Policy content.
    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.token_broker
            .get_policy(policy_id)
            .await
            .context("Cannot Get Policy")
    }

    /// Evaluate Attestation Evidence.
    /// Issue an attestation results token which contain TCB status and TEE public key. Input parameters:
    /// - `evidence`: TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    ///   are in `verifier` crate.
    /// - `tee`: concrete TEE type
    /// - `runtime_data`: These data field will be used to check against the counterpart inside the evidence.
    ///   The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    ///   will not be performed.
    /// - `init_data`: These data field will be used to check against the counterpart inside the evidence.
    ///   The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    ///   will not be performed.
    /// - `hash_algorithm`: The hash algorithm that is used to calculate the digest of `runtime_data` and
    ///   `init_data`.
    /// - `policy_ids`: The ids of the policies that will be used to evaluate the claims.
    ///    For EAR tokens, only the first policy will be evaluated.
    ///    The hash of the policy will be returned as part of the attestation token.
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
        let mut tee_claims: Vec<TeeClaims> = vec![];
        let guest_evidence: GuestEvidence = serde_json::from_slice(&evidence)?;

        // Parse init_data, which is shared by primary and additonal verifiers
        let (init_data, init_data_claims) =
            parse_data(init_data, &init_data_hash_algorithm).context("parse init data")?;

        let init_data_hash = match &init_data {
            Some(data) => InitDataHash::Value(data),
            None => InitDataHash::NotProvided,
        };

        // Extend the primary runtime data to include the evidence from the additional
        // attesters
        let mut primary_runtime_data = runtime_data.clone();
        match primary_runtime_data {
            Some(Data::Structured(ref mut data)) => match data.as_object_mut() {
                Some(data_object) => {
                    data_object.insert(
                        "additional-evidence".to_string(),
                        json!(guest_evidence.additional_evidence),
                    );
                }
                _ => bail!("Malformed structured runtime data."),
            },
            // Since the runtime_data must be extended to validate the
            // evidence of the additional attesters, we cannot support
            // raw runtime data.
            _ => bail!("Runtime data must be structured JSON data"),
        };

        let (primary_report_data, _primary_runtime_data_claims) =
            parse_data(primary_runtime_data, &runtime_data_hash_algorithm)
                .context("parse runtime data")?;

        let primary_report_data = match &primary_report_data {
            Some(data) => ReportData::Value(data),
            None => ReportData::NotProvided,
        };

        // Validate the evidence from the primary attester
        let primary_evidence = guest_evidence.primary_evidence;
        let primary_verifier = verifier::to_verifier(&tee)?;

        let primary_claims = primary_verifier
            .evaluate(
                primary_evidence.clone(),
                &primary_report_data,
                &init_data_hash,
            )
            .await
            .map_err(|e| anyhow!("Primary verifier evaluate failed: {e:?}"))?;
        info!("{:?} Primary verifier/endorsement check passed.", tee);

        tee_claims.push(TeeClaims {
            tee,
            tee_class: guest_evidence.primary_tee_class,
            claims: primary_claims,
        });

        // Validate additional evidence
        let (additional_report_data, additional_runtime_data_claims) =
            parse_data(runtime_data, &runtime_data_hash_algorithm).context("parse runtime data")?;

        let additional_report_data = match &additional_report_data {
            Some(data) => ReportData::Value(data),
            None => ReportData::NotProvided,
        };

        // Parse additional evidence if present
        if guest_evidence.additional_evidence != "" {
            let additional_evidence: HashMap<Tee, (TeeClass, TeeEvidence)> =
                serde_json::from_str(&guest_evidence.additional_evidence)?;
            for (tee, (class, evidence)) in additional_evidence.iter() {
                let additional_verifier = verifier::to_verifier(tee)?;

                let additional_claims = additional_verifier
                    .evaluate(evidence.clone(), &additional_report_data, &init_data_hash)
                    .await
                    .map_err(|e| anyhow!("Primary verifier evaluate failed: {e:?}"))?;
                info!("{:?} Primary verifier/endorsement check passed.", tee);

                tee_claims.push(TeeClaims {
                    tee: *tee,
                    tee_class: class.clone(),
                    claims: additional_claims,
                });
            }
        }

        let reference_data_map = self
            .rvps
            .get_digests()
            .await
            .map_err(|e| anyhow!("Generate reference data failed: {:?}", e))?;
        debug!("reference_data_map: {:#?}", reference_data_map);

        let attestation_results_token = self
            .token_broker
            .issue(
                tee_claims,
                policy_ids,
                init_data_claims,
                additional_runtime_data_claims,
                reference_data_map,
                tee,
            )
            .await?;
        Ok(attestation_results_token)
    }

    /// Registry a new reference value
    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps
            .verify_and_extract(message)
            .await
            .context("register reference value")
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee)?;
        verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
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
