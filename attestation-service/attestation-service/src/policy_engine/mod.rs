use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;
use strum::EnumString;

pub mod opa;

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
    /// Verify an input body against a set of ref values and a list of policies
    /// return a list of policy ids with their sha384 at eval time
    /// abort early on first failed validation and any errors.
    /// The result is a key-value map.
    /// - `key`: the policy id
    /// - `value`: the digest of the policy (using **Sha384**).
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_ids: Vec<String>,
    ) -> Result<HashMap<String, PolicyDigest>>;

    async fn set_policy(&mut self, policy_id: String, policy: String) -> Result<()>;

    /// The result is a map. The key is the policy id, and the
    /// value is the digest of the policy (using **Sha384**).
    async fn list_policies(&self) -> Result<HashMap<String, PolicyDigest>>;

    async fn get_policy(&self, policy_id: String) -> Result<String>;
}
