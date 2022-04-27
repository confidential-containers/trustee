use super::{AttestationResults, Evidence};
use anyhow::Result;
use async_trait::async_trait;

pub mod policy;
pub mod sample;
pub mod sgx;
pub mod tdx;

#[async_trait]
pub trait Verifier {
    async fn evaluate(
        &self,
        evidence: &Evidence,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<AttestationResults>;
    fn default_policy(&self) -> Result<String>;
    fn default_reference_data(&self) -> Result<String>;
}
