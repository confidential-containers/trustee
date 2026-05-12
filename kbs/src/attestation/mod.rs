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

use anyhow::bail;
use kbs_types::{HashAlgorithm, Tee};
use serde_json::json;
use tracing::info;

/// JSON key for supported hash algorithms in TEE parameters
pub const SUPPORTED_HASH_ALGORITHMS_JSON_KEY: &str = "supported-hash-algorithms";

/// JSON key for selected hash algorithm in extra parameters
pub const SELECTED_HASH_ALGORITHM_JSON_KEY: &str = "selected-hash-algorithm";

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
pub mod error;
pub use error::*;
