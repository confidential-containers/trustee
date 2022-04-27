use anyhow::{anyhow, Result};
use super::*;
use async_trait::async_trait;
use crate::default_policy;
use crate::default_reference_data;

#[derive(Debug, Default)]
pub struct Sgx {}

#[async_trait]
impl Verifier for Sgx {
    async fn evaluate(
        &self,
        _evidence: &Evidence,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<AttestationResults> {
        // Use the default policy/reference_data if the input is None.
        let _policy = policy.unwrap_or(std::include_str!(default_policy!()).to_string());
        let _reference_data =
            reference_data.unwrap_or(std::include_str!(default_reference_data!()).to_string());

        Err(anyhow!("not implemented!"))
    }

    // Get the default OPA policy.
    fn default_policy(&self) -> Result<String> {
        Ok(std::include_str!(default_policy!()).to_string())
    }

    // Get the default OPA reference data.
    fn default_reference_data(&self) -> Result<String> {
        Ok(std::include_str!(default_reference_data!()).to_string())
    }
}
