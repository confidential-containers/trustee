use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use strum::EnumString;
use thiserror::Error;

use crate::rvps::RvpsClient;

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
    Base64DecodeFailed(#[from] base64::DecodeError),
    #[error("Illegal policy id. Only support alphabet, numeric, `-` or `_`")]
    InvalidPolicyId,
    #[error("Illegal policy: {0}")]
    InvalidPolicy(#[source] anyhow::Error),
    #[error("Failed to load reference data: {0}")]
    LoadReferenceDataFailed(#[source] anyhow::Error),
    #[error("Failed to set input data: {0}")]
    SetInputDataFailed(#[source] anyhow::Error),
    #[error("Failed to evaluate policy `{policy_id}`")]
    EvalPolicyFailed {
        policy_id: String,
        #[source]
        source: anyhow::Error,
    },
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
    pub fn to_policy_engine(&self, work_dir: &Path) -> Result<Arc<dyn PolicyEngine>> {
        match self {
            PolicyEngineType::OPA => {
                Ok(Arc::new(opa::OPA::new(work_dir.to_path_buf())?) as Arc<dyn PolicyEngine>)
            }
        }
    }
}

type PolicyDigest = String;

#[derive(Debug)]
pub struct EvaluationResult {
    pub trust_claims: Value,
    pub policy_hash: String,
}

#[async_trait]
pub trait PolicyEngine: Send + Sync {
    /// The inputs to an policy engine. Inspired by OPA, we divided the inputs
    /// into three parts:
    /// - `policy id`: indicates the policy id that will be used to perform policy
    /// enforcement
    /// - `data`: static data that will help to enforce the policy.
    /// - `input`: dynamic data that will help to enforce the policy.
    /// - `rules`: the decision statement to be executed by the policy engine
    /// to determine the final output.
    /// - `rvps_client`: a client that can be used to query reference values.
    ///
    /// In CoCoAS scenarios, `data` is recommended to carry reference values as
    /// it is relatively static. `input` is recommended to carry `tcb_claims`
    /// returned by `verifier` module. Concrete implementation can be different
    /// due to different needs.
    async fn evaluate(
        &self,
        data: Option<&str>,
        input: &str,
        policy_id: &str,
        rvps_client: Option<RvpsClient>,
    ) -> Result<EvaluationResult, PolicyError>;

    /// Add an additional policy to the AS that can be referenced by given policy id.
    /// The policy is expected to be provided as base 64.
    /// If overwrite is set to false, the policy will not be written if
    /// a policy with the same ID already exists.
    async fn set_policy(
        &self,
        policy_id: String,
        policy: String,
        overwrite: bool,
    ) -> Result<(), PolicyError>;

    /// The result is a map. The key is the policy id, and the
    /// value is the digest of the policy (using **Sha384**).
    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>, PolicyError>;

    async fn get_policy(&self, policy_id: String) -> Result<String, PolicyError>;
}
