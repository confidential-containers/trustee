// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! DICE certificate chain data structures.
//!
//! Based on TCG DICE Architecture Specification and the Tri-Secure paper §5.4.
//!
//! DICE chain: Root CA → DeviceID cert → Alias cert
//! Each layer carries FWID (Firmware ID) measurements.

use super::crypto;
use super::error::VerifierResult;
use p384::PublicKey;
use serde::{Deserialize, Serialize};

/// A firmware layer in the DICE measurement chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirmwareLayer {
    /// Layer name (e.g., "bootloader", "firmware", "OS")
    pub name: String,
    /// SHA-384 hash of the firmware image
    pub fwid: Vec<u8>,
    /// Version string
    pub version: String,
}

/// DeviceID certificate (first in the DICE chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdCert {
    /// Device serial number (manufacturer-assigned)
    pub serial: String,
    /// Device class identifier (e.g., "bluefield3")
    pub device_class: String,
    /// Firmware measurement layers (ordered, from boot ROM to final layer)
    pub firmware_layers: Vec<FirmwareLayer>,
    /// DeviceID public key (P-384 ECDSA)
    #[serde(with = "super::crypto::serde_pubkey")]
    pub public_key: PublicKey,
    /// Manufacturer Root CA signature over the cert TBS data
    pub root_ca_signature: Vec<u8>,
    /// Certificate validity: not-before (Unix timestamp)
    pub not_before: u64,
    /// Certificate validity: not-after (Unix timestamp)
    pub not_after: u64,
}

impl DeviceIdCert {
    /// Returns the accumulated FWID (hash of all layer FWIDs).
    pub fn accumulated_fwid(&self) -> Vec<u8> {
        let concatenated: Vec<u8> = self
            .firmware_layers
            .iter()
            .flat_map(|layer| layer.fwid.iter().copied())
            .collect();
        crypto::sha384(&concatenated)
    }

    /// Returns the TBS (to-be-signed) data for Root CA verification.
    pub fn tbs_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.serial.as_bytes());
        data.extend_from_slice(self.device_class.as_bytes());
        for layer in &self.firmware_layers {
            data.extend_from_slice(layer.fwid.as_slice());
        }
        data.extend(crypto::pubkey_to_bytes(&self.public_key));
        data.extend_from_slice(&self.not_before.to_le_bytes());
        data.extend_from_slice(&self.not_after.to_le_bytes());
        data
    }

    /// Checks certificate temporal validity.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.not_before && now <= self.not_after
    }
}

/// Alias certificate (second in the DICE chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasCert {
    /// Alias certificate serial (per-session)
    pub serial: String,
    /// Alias public key (P-384 ECDSA)
    #[serde(with = "super::crypto::serde_pubkey")]
    pub public_key: PublicKey,
    /// Session binding nonce (N_D, 32 bytes)
    pub session_nonce: Vec<u8>,
    /// Combined nonce hash H(N_C || N_G || N_D) for tri-core binding
    pub combined_nonce_hash: Vec<u8>,
    /// DPU's OOB hash set: H(E_CPU) and H(E_GPU)
    pub oob_hashes: OOBHashSet,
    /// Timestamp when Alias cert was generated
    pub timestamp: u64,
    /// DeviceID signature over the Alias cert TBS data
    pub device_id_signature: Vec<u8>,
}

/// Out-of-band hash set computed by the DPU.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OOBHashSet {
    /// SHA-384 hash of the CPU TDX Quote
    pub cpu_evidence_hash: Vec<u8>,
    /// SHA-384 hash of the GPU CC Report
    pub gpu_evidence_hash: Vec<u8>,
}

impl AliasCert {
    /// Returns the TBS (to-be-signed) data for DeviceID verification.
    pub fn tbs_data(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(self.serial.as_bytes());
        data.extend(crypto::pubkey_to_bytes(&self.public_key));
        data.extend_from_slice(&self.session_nonce);
        data.extend_from_slice(&self.combined_nonce_hash);
        data.extend_from_slice(&self.oob_hashes.cpu_evidence_hash);
        data.extend_from_slice(&self.oob_hashes.gpu_evidence_hash);
        data.extend_from_slice(&self.timestamp.to_le_bytes());
        data
    }
}

/// Complete DICE certificate chain from the DPU.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiceCertChain {
    /// DeviceID certificate (signed by Root CA)
    pub device_id_cert: DeviceIdCert,
    /// Alias certificate (signed by DeviceID key)
    pub alias_cert: AliasCert,
}

impl DiceCertChain {
    /// Deserializes a DICE cert chain from JSON.
    pub fn from_json(json: &str) -> VerifierResult<Self> {
        serde_json::from_str(json).map_err(Into::into)
    }

    /// Serializes to JSON.
    pub fn to_json(&self) -> VerifierResult<String> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Returns the total number of firmware layers measured.
    pub fn firmware_layer_count(&self) -> usize {
        self.device_id_cert.firmware_layers.len()
    }
}
