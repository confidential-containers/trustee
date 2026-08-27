use std::cmp::Ordering;
use std::sync::Arc;

use anyhow::*;
use async_trait::async_trait;
use kbs_types::Tee;
use key_value_storage::StorageProvider;
use serde::Deserialize;
use tracing::debug;

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

#[cfg(any(feature = "tdx-verifier", feature = "sgx-verifier"))]
pub(crate) mod intel_dcap;

#[cfg(feature = "tpm-verifier")]
pub mod tpm;

#[cfg(feature = "nvidia-dpu-verifier")]
pub mod nvidia_dpu;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct VerifierConfig {
    #[cfg(feature = "nvidia-verifier")]
    nvidia_verifier: Option<nvidia::NvidiaVerifierConfig>,

    #[cfg(feature = "tpm-verifier")]
    tpm_verifier: Option<tpm::TpmVerifierConfig>,

    #[cfg(feature = "snp-verifier")]
    snp_verifier: Option<snp::SnpVerifierConfig>,

    #[cfg(any(
        feature = "tdx-verifier",
        feature = "sgx-verifier",
        feature = "az-tdx-vtpm-verifier"
    ))]
    dcap_verifier: Option<intel_dcap::QcnlConfig>,

    #[cfg(feature = "nvidia-dpu-verifier")]
    nvidia_dpu_verifier: Option<nvidia_dpu::NvidiaDpuVerifierConfig>,
}

/// Build the [`Verifier`] for `tee`.
///
/// `storage` is a namespace provider: a verifier that needs to persist state
/// (e.g. cached DCAP collateral) mints its own namespace in-place with
/// `storage.get_or_register("intel-dcap-collateral")`. Verifiers that don't
/// need storage simply ignore it.
pub async fn to_verifier(
    tee: &Tee,
    _config: Option<VerifierConfig>,
    _storage: Arc<dyn StorageProvider>,
) -> Result<Box<dyn Verifier + Send + Sync>> {
    match tee {
        Tee::AzSnpVtpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-snp-vtpm-verifier")] {
                    let verifier = az_snp_vtpm::AzSnpVtpm;
                    Ok(Box::new(verifier) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `az-snp-vtpm-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::AzTdxVtpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "az-tdx-vtpm-verifier")] {
                    let dcap_config = _config.and_then(|c| c.dcap_verifier);
                    Ok(Box::new(az_tdx_vtpm::AzTdxVtpm::new(dcap_config)) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `az-tdx-vtpm-verifier` is not enabled for `verifier` crate.");
                }
            }
        }
        Tee::Tdx => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tdx-verifier")] {
                    let dcap_config = _config.and_then(|c| c.dcap_verifier);
                    Ok(Box::new(tdx::Tdx::new(dcap_config)) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `tdx-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
        Tee::Snp => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "snp-verifier")] {
                    let snp_config = _config.map(|c| c.snp_verifier).unwrap_or(None);
                    Ok(Box::<snp::Snp>::new(snp::Snp::new(snp_config).await?) as Box<dyn Verifier + Send + Sync>)
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
                    let dcap_config = _config.and_then(|c| c.dcap_verifier);
                    Ok(Box::new(sgx::SgxVerifier::new(dcap_config)) as Box<dyn Verifier + Send + Sync>)
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
                    let nvidia_config = _config.map(|c| c.nvidia_verifier).unwrap_or(None);
                    Ok(Box::<nvidia::Nvidia>::new(nvidia::Nvidia::new(nvidia_config).await?) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `nvidia-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::Tpm => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "tpm-verifier")] {
                    Ok(Box::<tpm::TpmVerifier>::default() as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `tpm-verifier` is not enabled for `verifier` crate.")
                }
            }
        }

        Tee::NvidiaDpu => {
            cfg_if::cfg_if! {
                if #[cfg(feature = "nvidia-dpu-verifier")] {
                    let config = _config.and_then(|c| c.nvidia_dpu_verifier)
                        .context("nvidia_dpu_verifier config is required")?;
                    Ok(Box::new(nvidia_dpu::NvidiaDpuVerifier::new(config)?) as Box<dyn Verifier + Send + Sync>)
                } else {
                    bail!("feature `nvidia-dpu-verifier` is not enabled for `verifier` crate.")
                }
            }
        }
    }
}

pub type TeeEvidenceParsedClaim = serde_json::Value;
pub type TeeClass = String;

/// Evidence as produced by an attester: an explicit format version alongside
/// the opaque, TEE-specific payload.
///
/// # Wire contract
///
/// Evidence is a single JSON object. Its format version is carried by an
/// optional top-level `version` field; everything else is the TEE-specific
/// payload:
///
/// ```json
/// { "version": 1, "tpm_quote": { /* ... */ } }   // explicit version 1
/// { "attestation_report": { /* ... */ } }        // legacy, implicit version 0
/// ```
///
/// The `version` must be a top-level field named exactly `version` and must
/// be representable as a `u8`. If `version` is not provided, it defaults to `0`
/// (legacy).
///
/// [`data`](Self::data) holds the whole payload verbatim (including the
/// `version` field, if any). TEE verifiers deserialize [`data`](Self::data) into their
/// own concrete evidence type.
///
/// Which versions are *supported* is a separate concern that belongs to the
/// [`Verifier`] (see [`Verifier::max_supported_version`]).
#[derive(Clone, Debug, PartialEq)]
pub struct TeeEvidence {
    /// The evidence format version, read from the top-level `version` field at
    /// parse time. Legacy evidence without an explicit version is `0`.
    pub version: u8,
    /// The raw TEE-specific evidence payload, verbatim.
    pub data: serde_json::Value,
}

/// Read a top-level `version` value as a `u8`. Returns `Ok(None)` when absent,
/// `Err` when present but not representable as a `u8`.
fn parse_version_field(value: &serde_json::Value) -> Result<Option<u8>> {
    let Some(v) = value.get("version") else {
        return Ok(None);
    };

    let Some(version) = v.as_u64().and_then(|n| u8::try_from(n).ok()) else {
        bail!("invalid evidence version: {v}");
    };

    Ok(Some(version))
}

impl From<serde_json::Value> for TeeEvidence {
    fn from(value: serde_json::Value) -> Self {
        let version = parse_version_field(&value).unwrap_or(None).unwrap_or(0);
        TeeEvidence {
            version,
            data: value,
        }
    }
}

impl<'de> Deserialize<'de> for TeeEvidence {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Read the payload as an opaque value once, then validate the version
        // contract up front. This happens before any TEE-specific variant
        // matching, so a malformed version yields a clear error rather than an
        // opaque "failed to deserialize" later on.
        let value = serde_json::Value::deserialize(deserializer)?;
        let version = parse_version_field(&value)
            .map_err(<D::Error as serde::de::Error>::custom)?
            .unwrap_or(0);
        // Qualified: `use anyhow::*` shadows `Ok` with `anyhow::Ok`.
        std::result::Result::Ok(TeeEvidence {
            version,
            data: value,
        })
    }
}

impl serde::Serialize for TeeEvidence {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // The payload is the wire form: it already carries `version`, so emitting
        // it verbatim round-trips back to the same evidence.
        self.data.serialize(serializer)
    }
}

/// Reject evidence whose version exceeds what `verifier` supports, with a
/// uniform, user-facing error message.
///
/// This is the generic version guard: it belongs to the dispatch layer, not to
/// any individual TEE, and should be called before [`Verifier::evaluate`].
pub fn check_evidence_version(
    verifier: &dyn Verifier,
    evidence: &TeeEvidence,
    tee: &Tee,
) -> Result<()> {
    let max = verifier.max_supported_version();
    let version = evidence.version;
    if version > max {
        bail!(
            "Unsupported {tee:?} evidence version {version}. This verifier \
             supports evidence versions 0-{max}",
        );
    }
    Ok(())
}

/// Insert a verified eventlog as a `uefi_event_logs` claim -- a no-op if
/// `ccel` is `None`.
#[cfg(feature = "az-snp-vtpm-verifier")]
pub(crate) fn extend_eventlog_claim(
    claim: &mut TeeEvidenceParsedClaim,
    ccel: Option<eventlog::CcEventLog>,
) -> Result<()> {
    let Some(ccel) = ccel else {
        return Ok(());
    };

    let serde_json::Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    map.insert(
        "uefi_event_logs".to_string(),
        serde_json::to_value(ccel.log)?,
    );

    Ok(())
}

pub enum ReportData<'a> {
    Value(&'a [u8]),
    NotProvided,
}

pub enum InitDataHash<'a> {
    Value(&'a [u8]),
    NotProvided,
}

/// Trait for converting types to hex strings
pub trait ToHex {
    fn to_hex(&self) -> String;
}

impl ToHex for ReportData<'_> {
    fn to_hex(&self) -> String {
        match self {
            ReportData::Value(bytes) => hex::encode(bytes),
            ReportData::NotProvided => String::new(),
        }
    }
}

#[async_trait]
pub trait Verifier {
    /// The highest evidence format version this verifier understands.
    ///
    /// Support for evidence versions is a property of the verifier, not of the
    /// evidence itself. The default is `0` (legacy evidence only); a verifier
    /// opts in to newer formats by overriding this and handling the additional
    /// versions in [`evaluate`](Verifier::evaluate).
    fn max_supported_version(&self) -> u8 {
        0
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::json;

    #[test]
    fn evidence_without_version_is_legacy_zero() {
        let ev: TeeEvidence = serde_json::from_value(json!({ "foo": "bar" })).unwrap();
        assert_eq!(ev.version, 0);
        // The payload is preserved verbatim.
        assert_eq!(ev.data, json!({ "foo": "bar" }));
    }

    #[test]
    fn evidence_reads_top_level_version() {
        let ev: TeeEvidence =
            serde_json::from_value(json!({ "version": 2, "foo": "bar" })).unwrap();
        assert_eq!(ev.version, 2);
        // The version field stays inside the payload handed to the verifier.
        assert_eq!(ev.data, json!({ "version": 2, "foo": "bar" }));
    }

    #[test]
    fn non_u8_version_is_a_deserialization_error() {
        // A version that is not a u8 (e.g. a date string) must fail clearly
        // rather than being silently ignored.
        let err = serde_json::from_value::<TeeEvidence>(json!({ "version": "2026-05-24" }))
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid evidence version"), "got: {err}");
    }

    #[test]
    fn version_only_applies_to_top_level() {
        // A nested `version` must not be mistaken for the evidence version.
        let ev: TeeEvidence = serde_json::from_value(json!({ "inner": { "version": 3 } })).unwrap();
        assert_eq!(ev.version, 0);
    }

    #[test]
    fn from_value_reads_version_leniently() {
        let ev: TeeEvidence = json!({ "version": 1 }).into();
        assert_eq!(ev.version, 1);
        // A non-u8 version via the infallible `From` path reads as legacy.
        let ev: TeeEvidence = json!({ "version": "nope" }).into();
        assert_eq!(ev.version, 0);
    }

    #[test]
    fn evidence_serializes_back_to_its_payload() {
        // Serialization emits the payload verbatim, so it round-trips.
        let data = json!({ "version": 1, "foo": "bar" });
        let ev = TeeEvidence::from(data.clone());
        assert_eq!(serde_json::to_value(&ev).unwrap(), data);

        // Legacy (unversioned) evidence round-trips too.
        let legacy = json!({ "foo": "bar" });
        let ev = TeeEvidence::from(legacy.clone());
        assert_eq!(serde_json::to_value(&ev).unwrap(), legacy);
    }

    // Minimal verifier used to exercise the generic version guard.
    struct DummyVerifier {
        max: u8,
    }

    #[async_trait]
    impl Verifier for DummyVerifier {
        fn max_supported_version(&self) -> u8 {
            self.max
        }

        async fn evaluate(
            &self,
            _evidence: TeeEvidence,
            _expected_report_data: &ReportData,
            _expected_init_data_hash: &InitDataHash,
        ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
            Ok(vec![])
        }
    }

    #[test]
    fn check_version_accepts_supported_and_legacy() {
        let verifier = DummyVerifier { max: 1 };
        for v in [json!({}), json!({ "version": 1 })] {
            let ev = TeeEvidence::from(v);
            assert!(check_evidence_version(&verifier, &ev, &Tee::Snp).is_ok());
        }
    }

    #[test]
    fn check_version_rejects_too_new_with_clear_error() {
        let verifier = DummyVerifier { max: 1 };
        let ev = TeeEvidence::from(json!({ "version": 99 }));
        let err = check_evidence_version(&verifier, &ev, &Tee::Snp)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Unsupported"), "got: {err}");
        assert!(err.contains("version 99"), "got: {err}");
        assert!(err.contains("versions 0-1"), "got: {err}");
    }

    #[test]
    fn default_verifier_supports_only_legacy() {
        let verifier = DummyVerifier { max: 0 };
        assert_eq!(verifier.max_supported_version(), 0);
        let ev = TeeEvidence::from(json!({ "version": 1 }));
        assert!(check_evidence_version(&verifier, &ev, &Tee::Snp).is_err());
    }
}
