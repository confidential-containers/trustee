use crate::types::TeeEvidenceParsedClaim;
use anyhow::Result;
use async_trait::async_trait;
use kbs_types::{Attestation, Tee};

pub mod sample;

#[cfg(feature = "sample_verifier")]
pub(crate) fn to_verifier(_tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    Ok(Box::new(sample::Sample::default()) as Box<dyn Verifier + Send + Sync>)
}

#[cfg(not(feature = "sample_verifier"))]
pub(crate) fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    match tee {
        Tee::Sev | Tee::Sgx | Tee::Snp | Tee::Tdx => todo!(),
    }
}

#[async_trait]
pub trait Verifier {
    /// Verify the hardware signature and report data in TEE quote.
    /// If the verification is successful, a key-value pairs map of TCB status will be returned,
    /// The policy engine of AS will carry out the verification of TCB status.
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim>;
}
