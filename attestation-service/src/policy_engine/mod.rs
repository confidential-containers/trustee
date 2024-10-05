use anyhow::Result;
use async_trait::async_trait;
use ear::{Appraisal, RawValue};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::Path;
use strum::EnumString;
use thiserror::Error;

pub mod opa;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Failed to create policy directory: {0}")]
    CreatePolicyDirFailed(#[source] io::Error),
    #[error("Failed to convert policy directory path to string")]
    PolicyDirPathToStringFailed,
    #[error("Failed to write default policy: {0}")]
    WriteDefaultPolicyFailed(#[source] io::Error),
    #[error("Failed to read attestation service policy file: {0}")]
    ReadPolicyFileFailed(#[source] io::Error),
    #[error("Failed to write attestation service policy to file: {0}")]
    WritePolicyFileFailed(#[source] io::Error),
    #[error("Failed to load policy: {0}")]
    LoadPolicyFailed(#[source] anyhow::Error),
    #[error("Policy evaluation denied for {policy_id}")]
    PolicyDenied { policy_id: String },
    #[error("Serde json error: {0}")]
    SerdeJsonError(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Base64 decode attestation service policy string failed: {0}")]
    Base64DecodeFailed(#[source] base64::DecodeError),
    #[error("Illegal policy id. Only support alphabet, numeric, `-` or `_`")]
    InvalidPolicyId,
    #[error("Failed to load reference data: {0}")]
    LoadReferenceDataFailed(#[source] anyhow::Error),
    #[error("Failed to set input data: {0}")]
    SetInputDataFailed(#[source] anyhow::Error),
    #[error("Failed to evaluate policy: {0}")]
    EvalPolicyFailed(#[source] anyhow::Error),
    #[error("json serialization failed: {0}")]
    JsonSerializationFailed(#[source] anyhow::Error),
    #[error("Policy claim value not valid (must be between -127 and 127)")]
    InvalidClaimValue,
}

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    OPA,
}

impl PolicyEngineType {
    pub fn to_policy_engine(&self, work_dir: &Path) -> Result<Box<dyn PolicyEngine + Send + Sync>> {
        match self {
            PolicyEngineType::OPA => Ok(Box::new(opa::OPA::new(work_dir.to_path_buf())?)
                as Box<dyn PolicyEngine + Send + Sync>),
        }
    }
}

type PolicyDigest = String;

#[async_trait]
pub trait PolicyEngine {
    /// Verify an input body against a set of ref values and a policy id
    /// return an EAR Appraisal
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        tcb_claims: BTreeMap<String, RawValue>,
        policy_id: String,
    ) -> Result<Appraisal, PolicyError>;

    async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<(), PolicyError>;

    /// The result is a map. The key is the policy id, and the
    /// value is the digest of the policy (using **Sha384**).
    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError>;

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError>;
}
