use anyhow::Result;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

pub mod opa;

#[derive(Debug, EnumString, Deserialize)]
#[strum(ascii_case_insensitive)]
pub enum PolicyEngineType {
    OPA,
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

pub trait PolicyEngine {
    fn evaluate(
        &self,
        reference_data_map: HashMap<String, Vec<String>>,
        input: String,
    ) -> Result<(bool, String)>;
}
