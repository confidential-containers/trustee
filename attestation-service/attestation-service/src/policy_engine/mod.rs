use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use strum::EnumString;

pub mod opa;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SetPolicyInput {
    pub r#type: String,
    pub policy_id: String,
    pub policy: String,
}

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    OPA,
}

#[derive(Debug, EnumString, Deserialize, PartialEq)]
#[strum(ascii_case_insensitive)]
pub enum PolicyType {
    Rego,
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
type EvaluationResult = serde_json::Value;

#[async_trait]
pub trait PolicyEngine {
    /// The result is a key-value map.
    /// - `key`: the policy id
    /// - `value`: It will be a tuple. The first element is the digest of
    /// the policy (using **Sha384**). The second element is the evaluation
    /// output of the policy.
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_ids: Vec<String>,
    ) -> Result<HashMap<String, (PolicyDigest, EvaluationResult)>>;

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()>;
}
