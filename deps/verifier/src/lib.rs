use std::cmp::Ordering;

use anyhow::*;
use async_trait::async_trait;
use kbs_types::Tee;
use log::debug;

pub mod sample;
pub mod sample_device;

#[cfg(feature = "az-snp-vtpm-verifier")]
pub mod az_snp_vtpm;

#[cfg(feature = "az-tdx-vtpm-verifier")]
pub mod az_tdx_vtpm;

#[cfg(feature = "snp-verifier")]
pub mod snp;

#[cfg(feature = "tdx-verifier")]
pub mod tdx;

#[cfg(feature = "sgx-verifier")]
pub mod sgx;

#[cfg(feature = "csv-verifier")]
pub mod csv;

#[cfg(feature = "hygon-dcu-verifier")]
pub mod hygon_dcu;

#[cfg(feature = "cca-verifier")]
pub mod cca;

#[cfg(feature = "se-verifier")]
pub mod se;

#[cfg(feature = "nvidia-verifier")]
pub mod nvidia;

#[cfg(any(
    feature = "az-tdx-vtpm-verifier",
    feature = "tdx-verifier",
    feature = "sgx-verifier"
))]
pub mod intel_dcap;

#[cfg(feature = "tpm-verifier")]
pub mod tpm;

pub fn to_verifier(tee: &Tee) -> Result<Box<dyn Verifier + Send + Sync>> {
    match tee {
        Tee::Sev => todo!(),
        Tee::AzSnpVtpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-snp-vtpm-verifier")] {
                    let verifier = az_snp_vtpm::AzSnpVtpm::new()?;
                    Ok(Box::new(verifier) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `az-snp-vtpm-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::AzTdxVtpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-tdx-vtpm-verifier")] {
                    Ok(Box::<az_tdx_vtpm::AzTdxVtpm>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `az-tdx-vtpm-verifier` is not enabled for `verifier` crate.");
                }
            }
        }
        Tee::Tdx => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tdx-verifier")] {
                    Ok(Box::<tdx::Tdx>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `tdx-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Snp => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "snp-verifier")] {
                    let verifier = snp::Snp::default();
                    Ok(Box::new(verifier) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `snp-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Sample => Ok(Box::<sample::Sample>::default() as Box<dyn Verifier + Send + Sync>),
        Tee::SampleDevice => Ok(Box::<sample_device::SampleDeviceVerifier>::default()
            as Box<dyn Verifier + Send + Sync>),
        Tee::Sgx => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "sgx-verifier")] {
                    Ok(Box::<sgx::SgxVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `sgx-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::Csv => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "csv-verifier")] {
                    Ok(Box::<csv::CsvVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `csv-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::Cca => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "cca-verifier")] {
                    Ok(Box::<cca::CCA>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `cca-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::Se => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "se-verifier")] {
                    Ok(Box::<se::SeVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `se-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::HygonDcu => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "hygon-dcu-verifier")] {
                    Ok(Box::<hygon_dcu::HygonDcuVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `hygon-dcu-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::Nvidia => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "nvidia-verifier")] {
                    Ok(Box::<nvidia::Nvidia>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `nvidia-verifier` is not enabled for `verifier` crate.")

                }
            }
        }
        Tee::Tpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tpm-verifier")] {
                    let config_path = std::env::var("TPM_CONFIG_FILE")
                        .unwrap_or_else(|_| "/etc/tpm_verifier.json".to_string());
                    log::info!("Using TPM config file: {}", config_path);
                    let config = match tpm::config::Config::try_from(std::path::Path::new(&config_path)) {
                        std::result::Result::Ok(c) => c.tpm_verifier,
                        std::result::Result::Err(e) => {
                            log::warn!("Failed to load TPM config file: {}. Using default.", e);
                            tpm::config::TpmVerifierConfig::default()
                        }
                    };

                    let verifier = tpm::TpmVerifier::new(config)?;
                    Ok(Box::new(verifier) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `tpm-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
    }
}

pub type TeeEvidenceParsedClaim = serde_json::Value;
pub type TeeEvidence = serde_json::Value;
pub type TeeClass = String;

pub enum ReportData<'a> {
    Value(&'a [u8]),
    NotProvided,
}

pub enum InitDataHash<'a> {
    Value(&'a [u8]),
    NotProvided,
}

#[async_trait]
pub trait Verifier {
    /// Verify the hardware signature.
    ///
    ///
    /// `evidence` is JSON data generated by the corresponding attester.
    /// The evidence usually contains some raw bytes as well as additional
    /// context information from the attester.
    ///
    ///
    /// If `report_data` is given, the binding of the `report_data`
    /// against the `report_data` inside the hardware evidence will
    /// be checked. So do `init_data_hash`.
    ///
    ///
    /// Semantically, a `report_data` is a byte slice given when
    /// a hardware evidence is generated. The `report_data` will be
    /// included inside the hardware evidence, thus its integrity will
    /// be protected by the signature of the hardware.
    ///
    ///
    /// A `init_data_hash` is another byte slice given when the TEE
    /// instance is created. It is always provided by untrusted host,
    /// but its integrity will be protected by the tee evidence.
    /// Typical `init_data_hash` is `HOSTDATA` for SNP.
    ///
    ///
    /// There will be two claims by default regardless of architectures:
    /// - `init_data_hash`: init data hash of the evidence
    /// - `report_data`: report data of the evidence
    /// TODO: See https://github.com/confidential-containers/trustee/issues/228
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>>;

    /// Generate the supplemental challenge
    ///
    /// Some TEE like IBM SE need a `challenge` generated on verifier side
    /// and pass it to attester side. This challenge is used by attester to
    /// generate the evidence
    ///
    /// A optional `tee_parameters` comes from the attester side as the input.
    async fn generate_supplemental_challenge(&self, _tee_parameters: String) -> Result<String> {
        Ok(String::new())
    }
}

/// Padding or truncate the given data slice to the given `len` bytes.
pub fn regularize_data(data: &[u8], len: usize, data_name: &str, arch: &str) -> Vec<u8> {
    let data_len = data.len();
    match data_len.cmp(&len) {
        Ordering::Less => {
            debug!("The input {data_name} of {arch} is shorter than {len} bytes, will be padded with '\\0'.");
            let mut data = data.to_vec();
            data.resize(len, b'\0');
            data
        }
        Ordering::Equal => data.to_vec(),
        Ordering::Greater => {
            debug!("The input {data_name} of {arch} is longer than {len} bytes, will be truncated to {len} bytes.");
            data[..len].to_vec()
        }
    }
}
