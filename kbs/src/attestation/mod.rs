// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "coco-as")]
pub mod coco;

#[cfg(feature = "intel-trust-authority-as")]
pub mod intel_trust_authority;

pub mod backend;
pub mod config;
pub mod session;

pub use backend::AttestationService;

use anyhow::{bail, Context};
use kbs_types::{HashAlgorithm, Tee};
use serde::Deserialize;
use serde_json::json;
use tracing::info;

/// JSON key for supported hash algorithms in TEE parameters
pub const SUPPORTED_HASH_ALGORITHMS_JSON_KEY: &str = "supported-hash-algorithms";

/// JSON key for selected hash algorithm in extra parameters
pub const SELECTED_HASH_ALGORITHM_JSON_KEY: &str = "selected-hash-algorithm";

/// JSON key with which a client selects attestation policies in the extra
/// parameters of an RCAR `Request`
pub const ATTESTATION_POLICY_SELECTOR_JSON_KEY: &str = "attestation-policy-selector";

/// JSON key in a `Request`'s extra parameters carrying TEE metadata.
///
/// This matches `kbs_protocol`'s `tee-metadata` field: a `TotalTeeInfo` value
/// serialized next to the other request-wide parameters.
pub const TEE_METADATA_JSON_KEY: &str = "tee-metadata";

/// Primary and additional TEEs reported by the KBC.
///
/// Field names match `kbs_protocol::evidence_provider::TotalTeeInfo`.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct TotalTeeInfo {
    pub primary_tee: TeeInfo,
    pub additional_tees: Vec<TeeInfo>,
}

/// One TEE and the optional metadata its attester supplied.
///
/// Field names match `kbs_protocol::evidence_provider::TeeInfo`. `metadata` is
/// omitted on the wire when the attester has nothing to report.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct TeeInfo {
    pub tee: Tee,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
}

/// Read `extra-params.tee-metadata` and return the primary TEE's metadata.
///
/// `extra-params` is optional. The primary TEE is compared with `Request.tee`
/// only when `tee-metadata` is present.
pub fn primary_tee_metadata(
    tee: Tee,
    extra_params: &serde_json::Value,
) -> anyhow::Result<Option<serde_json::Value>> {
    let Some(raw) = extra_params
        .as_object()
        .and_then(|params| params.get(TEE_METADATA_JSON_KEY))
    else {
        return Ok(None);
    };

    let info: TotalTeeInfo =
        serde_json::from_value(raw.clone()).context("failed to deserialize tee-metadata")?;
    if info.primary_tee.tee != tee {
        bail!(
            "tee-metadata primary TEE {:?} does not match request TEE {tee:?}",
            info.primary_tee.tee
        );
    }

    Ok(info.primary_tee.metadata)
}

/// Generate extra parameters for TEE hash algorithm negotiation.
///
/// This function checks if the provided TEE parameters contain supported hash algorithms
/// and selects a hash algorithm based on the TEE type if available.
/// Returns a JSON value with the selected algorithm,
/// or an empty string if negotiation is not applicable.
///
/// Currently only applies to SE (Secure Execution) TEE type.
///
/// # Errors
///
/// Returns an error if:
/// - The hash algorithms field is not an array
/// - The required hash algorithm is not supported by the TEE
pub fn generate_extra_params(
    tee: Tee,
    tee_parameters: &serde_json::Value,
) -> anyhow::Result<serde_json::Value> {
    let extra_params = match tee {
        Tee::Se if !tee_parameters.is_null() => {
            if let Some(hash_algorithms_found) =
                tee_parameters.get(SUPPORTED_HASH_ALGORITHMS_JSON_KEY)
            {
                let Some(algorithms) = hash_algorithms_found.as_array() else {
                    bail!("SE expected hash algorithm array, found {hash_algorithms_found:?}");
                };

                let supported_hash_algorithms: Vec<String> = algorithms
                    .iter()
                    .filter_map(|value| Some(value.as_str()?.to_lowercase()))
                    .collect();

                let needed_algorithm = HashAlgorithm::Sha512.as_ref().to_string().to_lowercase();

                if !supported_hash_algorithms.contains(&needed_algorithm) {
                    bail!("SE TEE does not support {needed_algorithm}");
                }

                json!({
                    SELECTED_HASH_ALGORITHM_JSON_KEY: needed_algorithm,
                })
            } else {
                info!("SE TEE parameters missing supported hash algorithms");
                serde_json::Value::String(String::new())
            }
        }
        _ => serde_json::Value::String(String::new()),
    };

    Ok(extra_params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_kbs_protocol_tee_metadata() {
        let extra_params = json!({
            "supported-hash-algorithms": ["sha384", "sha512"],
            "tee-metadata": {
                "primary_tee": {
                    "tee": "se",
                    "metadata": { "host": "lpar" }
                },
                "additional_tees": [
                    { "tee": "nvidia" }
                ]
            }
        });

        let metadata = primary_tee_metadata(Tee::Se, &extra_params).unwrap();
        assert_eq!(metadata, Some(json!({ "host": "lpar" })));
    }

    #[test]
    fn missing_tee_metadata_yields_no_metadata() {
        assert!(primary_tee_metadata(Tee::Sample, &json!({}))
            .unwrap()
            .is_none());
    }

    #[test]
    fn skips_primary_tee_check_without_tee_metadata() {
        for extra_params in [
            serde_json::Value::Null,
            json!(""),
            json!({ "supported-hash-algorithms": ["sha384"] }),
        ] {
            assert!(
                primary_tee_metadata(Tee::Tdx, &extra_params)
                    .unwrap()
                    .is_none(),
                "extra-params: {extra_params}"
            );
        }
    }

    #[test]
    fn rejects_primary_tee_mismatch() {
        let extra_params = json!({
            "tee-metadata": {
                "primary_tee": { "tee": "snp" },
                "additional_tees": []
            }
        });

        assert!(primary_tee_metadata(Tee::Tdx, &extra_params).is_err());
    }
}

pub mod error;
pub use error::*;
