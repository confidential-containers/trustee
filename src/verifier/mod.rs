use anyhow::Result;
use as_types::TeeEvidenceParsedClaim;
use async_trait::async_trait;
use kbs_types::{Attestation, Tee};

pub mod sample;

#[cfg(feature = "tdx-verifier")]
pub mod tdx;

pub(crate) fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    match tee {
        Tee::Sev | Tee::Sgx | Tee::Snp => todo!(),
        Tee::Tdx => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tdx-verifier")] {
                    Ok(Box::<tdx::Tdx>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    todo!()
                }
            }
        }
        Tee::Sample => Ok(Box::<sample::Sample>::default() as Box<dyn Verifier + Send + Sync>),
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
