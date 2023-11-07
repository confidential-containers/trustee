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
    #[allow(dead_code)]
    pub fn to_policy_engine(&self, work_dir: &Path) -> Result<Box<dyn PolicyEngine + Send + Sync>> {
        match self {
            PolicyEngineType::OPA => Ok(Box::new(opa::OPA::new(work_dir.to_path_buf())?)
                as Box<dyn PolicyEngine + Send + Sync>),
        }
    }
}

#[async_trait]
pub trait PolicyEngine {
    async fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
        policy_id: Option<String>,
    ) -> Result<String>;

    async fn set_policy(&mut self, input: SetPolicyInput) -> Result<()>;
}
