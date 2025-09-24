//! Attestation Service
//!
//! # Features
//! - `rvps-grpc`: The AS will connect a remote RVPS.

pub mod config;
pub mod policy_engine;
pub mod rvps;
pub mod token;

use crate::token::AttestationTokenBroker;

use canon_json::CanonicalFormatter;
pub use kbs_types::{Attestation, HashAlgorithm, Tee};
pub use serde_json::Value;

use anyhow::{anyhow, bail, Context, Result};
use config::Config;
use log::{debug, info};
use rvps::{RvpsApi, RvpsError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use tokio::fs;
use verifier::{InitDataHash, ReportData, TeeEvidenceParsedClaim};

fn serialize_canon_json<T: Serialize>(value: T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser)?;
    Ok(buf)
}

pub type TeeEvidence = serde_json::Value;
pub type TeeClass = String;

/// Tee Claims are the output of the verifier plus some metadata
/// that identifies the TEE type and class.
#[derive(Debug)]
pub struct TeeClaims {
    tee: Tee,
    tee_class: TeeClass,
    claims: TeeEvidenceParsedClaim,
    init_data_claims: serde_json::Value,
    runtime_data_claims: serde_json::Value,
}

/// Runtime Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug)]
pub enum RuntimeData {
    /// This will be used as the expected runtime data to check against
    /// the one inside evidence.
    Raw(Vec<u8>),

    /// Runtime data in a JSON map. CoCoAS will rearrange each layer of the
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

/// Initdata defined in
/// <https://github.com/confidential-containers/trustee/blob/47d7a2338e0be76308ac19be5c0c172c592780aa/kbs/docs/initdata.md>
#[derive(Debug, Deserialize, Serialize)]
pub struct Initdata {
    pub version: String,
    pub algorithm: HashAlgorithm,
    pub data: HashMap<String, String>,
}

/// Init Data used to check the binding relationship with report data
/// in Evidence
#[derive(Debug)]
pub enum InitDataInput {
    /// This will be used as the expected init data to check against
    /// the one inside evidence.
    Digest(Vec<u8>),

    /// Init data TOML. CoCoAS will perform hash calculation on the whole
    /// to check against the one inside evidence.
    ///
    /// After the verification, the `.data` field of init data field will
    /// be included inside the token claims.
    Toml(String),
}

/// A VerificationRequest contains hw evidence that the AS will verify along with some
/// metadata required for verification.
///
pub struct VerificationRequest {
    /// TEE evidence bytes. This might not be the raw hardware evidence bytes. Definitions
    /// are in `verifier` crate.
    pub evidence: TeeEvidence,
    /// concrete TEE type
    pub tee: Tee,
    /// These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    pub runtime_data: Option<RuntimeData>,
    /// The hash algorithm that is used to calculate the digest of `runtime_data`.
    pub runtime_data_hash_algorithm: HashAlgorithm,
    /// These data field will be used to check against the counterpart inside the evidence.
    /// The concrete way of checking is decide by the enum type. If this parameter is set `None`, the comparation
    /// will not be performed.
    pub init_data: Option<InitDataInput>,
}

pub struct AttestationService {
    config: Config,
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

        let token_broker = config.attestation_token_broker.to_token_broker().await?;

        Ok(Self {
            config,
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
    /// Issue an attestation results token which contain TCB status and TEE public key.
    /// An evaluation can cover one more pieces of TEE Evidence which represent the TCB.
    /// The results will be combined into one attestation token.
    /// For more information, see the definition of VerificationRequest above.
    pub async fn evaluate(
        &self,
        verification_requests: Vec<VerificationRequest>,
        policy_ids: Vec<String>,
    ) -> Result<String> {
        let mut tee_claims: Vec<TeeClaims> = vec![];

        if verification_requests.is_empty() {
            bail!("No verification requests provided.")
        }

        for verification_request in verification_requests {
            let verifier = verifier::to_verifier(
                &verification_request.tee,
                self.config.clone().verifier_config,
            )?;

            let (report_data, runtime_data_claims) = parse_runtime_data(
                verification_request.runtime_data,
                &verification_request.runtime_data_hash_algorithm,
            )
            .context("parse runtime data")?;

            let report_data = match &report_data {
                Some(data) => ReportData::Value(data),
                None => ReportData::NotProvided,
            };

            let (init_data, init_data_claims) =
                parse_init_data(verification_request.init_data).context("parse init data")?;

            let init_data_hash = match &init_data {
                Some(data) => InitDataHash::Value(data),
                None => InitDataHash::NotProvided,
            };

            let claims = verifier
                .evaluate(verification_request.evidence, &report_data, &init_data_hash)
                .await
                .map_err(|e| anyhow!("Verifier evaluate failed: {e:?}"))?;

            info!(
                "{:?} Verifier/endorsement check passed.",
                verification_request.tee
            );

            for (claims_from_tee_evidence, tee_class) in claims {
                tee_claims.push(TeeClaims {
                    tee: verification_request.tee,
                    tee_class,
                    claims: claims_from_tee_evidence,
                    init_data_claims: init_data_claims.clone(),
                    runtime_data_claims: runtime_data_claims.clone(),
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
            .issue(tee_claims, policy_ids, reference_data_map)
            .await?;
        Ok(attestation_results_token)
    }

    /// Register a new reference value
    pub async fn register_reference_value(&mut self, message: &str) -> Result<()> {
        self.rvps
            .verify_and_extract(message)
            .await
            .context("register reference value")
    }

    /// Query Reference Values
    pub async fn query_reference_values(&self) -> Result<HashMap<String, Value>> {
        self.rvps
            .get_digests()
            .await
            .context("query reference values")
    }

    pub async fn generate_supplemental_challenge(
        &self,
        tee: Tee,
        tee_parameters: String,
    ) -> Result<String> {
        let verifier = verifier::to_verifier(&tee, self.config.clone().verifier_config)?;
        verifier
            .generate_supplemental_challenge(tee_parameters)
            .await
    }
}

/// Get the expected runtime data and potential claims due to the given input
/// and the hash algorithm
fn parse_runtime_data(
    data: Option<RuntimeData>,
    hash_algorithm: &HashAlgorithm,
) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            RuntimeData::Raw(raw) => Ok((Some(raw), Value::Null)),
            RuntimeData::Structured(structured) => {
                // by default serde_json will enforence the alphabet order for keys
                let hash_materials =
                    serialize_canon_json(&structured).context("parse JSON structured data")?;
                let digest = hash_algorithm.digest(&hash_materials);
                Ok((Some(digest), structured))
            }
        },
        None => Ok((None, Value::Null)),
    }
}

/// Get the expected init data and potential claims due to the given input
/// and the hash algorithm
fn parse_init_data(data: Option<InitDataInput>) -> Result<(Option<Vec<u8>>, Value)> {
    match data {
        Some(value) => match value {
            InitDataInput::Digest(raw) => Ok((Some(raw), Value::Null)),
            InitDataInput::Toml(structured) => {
                let initdata = toml::from_str::<Initdata>(&structured)
                    .context("parse TOML structured data")?;
                let digest = initdata.algorithm.digest(&structured.into_bytes());
                let claims = serde_json::to_value(initdata.data)?;
                Ok((Some(digest), claims))
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

    use crate::{HashAlgorithm, RuntimeData};

    #[rstest]
    #[case(Some(RuntimeData::Raw(b"aaaaa".to_vec())), Some(b"aaaaa".to_vec()), HashAlgorithm::Sha384, Value::Null)]
    #[case(None, None, HashAlgorithm::Sha384, Value::Null)]
    #[case(Some(RuntimeData::Structured(json!({"b": 1, "a": "test", "c": {"d": "e"}}))), Some(hex::decode(b"e71ce8e70d814ba6639c3612ebee0ff1f76f650f8dbb5e47157e0f3f525cd22c4597480a186427c813ca941da78870c3").unwrap()), HashAlgorithm::Sha384, json!({"b": 1, "a": "test", "c": {"d": "e"}}))]
    fn parse_runtimedata_json_binding(
        #[case] input: Option<RuntimeData>,
        #[case] expected_data: Option<Vec<u8>>,
        #[case] hash_algorithm: HashAlgorithm,
        #[case] expected_claims: Value,
    ) {
        let (data, data_claims) =
            crate::parse_runtime_data(input, &hash_algorithm).expect("parse failed");
        assert_eq!(data, expected_data);
        assert_json_eq!(data_claims, expected_claims);
    }
}
