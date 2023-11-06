use anyhow::*;
use async_trait::async_trait;
use kbs_types::{Attestation, Tee};

pub mod sample;

#[cfg(feature = "az-snp-vtpm-verifier")]
pub mod az_snp_vtpm;

#[cfg(feature = "snp-verifier")]
pub mod snp;

#[cfg(feature = "tdx-verifier")]
pub mod tdx;

#[cfg(feature = "sgx-verifier")]
pub mod sgx;

#[cfg(feature = "csv-verifier")]
pub mod csv;

#[cfg(feature = "cca-verifier")]
pub mod cca;

pub(crate) fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    match tee {
        Tee::Sev => todo!(),
        Tee::AzSnpVtpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-snp-vtpm-verifier")] {
                    Ok(Box::<az_snp_vtpm::AzSnpVtpm>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    todo!()
                }
            }
        }
        Tee::Tdx => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tdx-verifier")] {
                    Ok(Box::<tdx::Tdx>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    todo!()
                }
            }
        }
        Tee::Snp => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "snp-verifier")] {
                    Ok(Box::<snp::Snp>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("SNP Verifier not enabled.")
                }
            }
        }
        Tee::Sample => Ok(Box::<sample::Sample>::default() as Box<dyn Verifier + Send + Sync>),
        Tee::Sgx => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "sgx-verifier")] {
                    Ok(Box::<sgx::SgxVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    anyhow::bail!("feature `sgx-verifier` is not enabled!");
                }
            }
        }

        Tee::Csv => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "csv-verifier")] {
                    Ok(Box::<csv::CsvVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    anyhow::bail!("feature `csv-verifier` is not enabled!");
                }
            }
        }

        Tee::Cca => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "cca-verifier")] {
                    Ok(Box::<cca::CCA>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    anyhow::bail!("feature `cca-verifier` is not enabled!");
                }
            }
        }
    }
}

pub type TeeEvidenceParsedClaim = serde_json::Value;

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
