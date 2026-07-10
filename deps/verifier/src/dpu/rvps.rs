// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! RVPS (Reference Value Provider Service) interface.
//!
//! The RVPS stores trusted reference measurements (FWIDs) that the verifier
//! compares against the DPU's DICE certificate chain measurements.

use super::dice::FirmwareLayer;
use super::error::{VerifierError, VerifierResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A reference value entry in the RVPS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceValue {
    /// Device class identifier (e.g., "bluefield3", "bluefield2")
    pub device_class: String,
    /// Firmware layer name
    pub layer_name: String,
    /// Expected firmware version
    pub expected_version: String,
    /// Expected FWID (SHA-384, 48 bytes)
    pub expected_fwid: Vec<u8>,
    /// Minimum required version (for downgrade protection)
    pub min_version: Option<String>,
}

/// RVPS client interface.
pub trait RvpsClient: Send + Sync {
    /// Look up reference values for a device class.
    fn get_reference_values(&self, device_class: &str) -> VerifierResult<Vec<ReferenceValue>>;

    /// Look up a specific reference value for a device class and layer.
    fn get_reference_value(
        &self,
        device_class: &str,
        layer_name: &str,
    ) -> VerifierResult<ReferenceValue>;
}

/// In-memory RVPS client for testing and development.
pub struct InMemoryRvps {
    values: HashMap<(String, String), ReferenceValue>,
}

impl InMemoryRvps {
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }

    pub fn insert(&mut self, rv: ReferenceValue) {
        let key = (rv.device_class.clone(), rv.layer_name.clone());
        self.values.insert(key, rv);
    }

    pub fn add_layer(
        &mut self,
        device_class: &str,
        layer_name: &str,
        version: &str,
        fwid: Vec<u8>,
    ) {
        self.insert(ReferenceValue {
            device_class: device_class.to_string(),
            layer_name: layer_name.to_string(),
            expected_version: version.to_string(),
            expected_fwid: fwid,
            min_version: None,
        });
    }
}

impl Default for InMemoryRvps {
    fn default() -> Self {
        Self::new()
    }
}

impl RvpsClient for InMemoryRvps {
    fn get_reference_values(&self, device_class: &str) -> VerifierResult<Vec<ReferenceValue>> {
        let result: Vec<ReferenceValue> = self
            .values
            .values()
            .filter(|rv| rv.device_class == device_class)
            .cloned()
            .collect();

        if result.is_empty() {
            Err(VerifierError::RvpsLookupFailed(device_class.to_string()))
        } else {
            Ok(result)
        }
    }

    fn get_reference_value(
        &self,
        device_class: &str,
        layer_name: &str,
    ) -> VerifierResult<ReferenceValue> {
        self.values
            .get(&(device_class.to_string(), layer_name.to_string()))
            .cloned()
            .ok_or_else(|| {
                VerifierError::RvpsLookupFailed(format!("{}/{}", device_class, layer_name))
            })
    }
}

/// Validates firmware layers against RVPS reference values.
pub fn validate_firmware_layers(
    layers: &[FirmwareLayer],
    device_class: &str,
    rvps: &dyn RvpsClient,
) -> VerifierResult<()> {
    for layer in layers {
        let rv = rvps.get_reference_value(device_class, &layer.name)?;

        // Check FWID match
        if layer.fwid != rv.expected_fwid {
            return Err(VerifierError::FwidMismatch {
                expected: hex::encode(&rv.expected_fwid),
                actual: hex::encode(&layer.fwid),
            });
        }

        // Check version (downgrade protection if min_version is set)
        if let Some(min_ver) = &rv.min_version {
            if version_lt(&layer.version, min_ver) {
                return Err(VerifierError::ChainValidation {
                    layer: layer.name.clone(),
                    reason: format!(
                        "firmware version {} below minimum {} (downgrade detected)",
                        layer.version, min_ver
                    ),
                });
            }
        }
    }
    Ok(())
}

/// Simple semver comparison: returns true if v1 < v2.
fn version_lt(v1: &str, v2: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.split('.')
            .filter_map(|n| n.parse().ok())
            .collect()
    };
    let parts1 = parse(v1);
    let parts2 = parse(v2);
    for i in 0..parts1.len().max(parts2.len()) {
        let a = parts1.get(i).copied().unwrap_or(0);
        let b = parts2.get(i).copied().unwrap_or(0);
        if a < b {
            return true;
        }
        if a > b {
            return false;
        }
    }
    false
}
