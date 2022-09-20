use crate::types::{Evidence, TeeEvidenceParsedClaim};
use anyhow::Result;
use async_trait::async_trait;

pub mod sample;

#[async_trait]
pub trait Verifier {
    /// Verify the hardware signature and report data in TEE quote.
    /// If the verification is successful, a key-value pairs map of TCB status will be returned,
    /// The policy engine of AS will carry out the verification of TCB status.
    async fn evaluate(&self, evidence: &Evidence) -> Result<TeeEvidenceParsedClaim>;
}
