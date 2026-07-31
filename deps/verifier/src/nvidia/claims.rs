// Copyright (c) 2026 by Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

use super::NvDeviceReportAndCertClaim;

/// Claims shared by local and remote NVIDIA GPU verifiers.
#[derive(Debug, Serialize)]
pub struct NvidiaGpuCommonClaims {
    /// GPU driver version (e.g. `550.90.07`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_version: Option<String>,

    /// GPU vBIOS version (e.g. `96.00.9F.00.01`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vbios_version: Option<String>,
}

/// GPU evidence claims
#[derive(Debug, Serialize)]
#[serde(tag = "verifier", rename_all = "lowercase")]
pub enum NvidiaGpuEvidenceClaims {
    /// Claims produced by the local Hopper verifier.
    Local {
        #[serde(flatten)]
        common: NvidiaGpuCommonClaims,
        arch: String,
        uuid: String,
        measurements: HashMap<u8, String>,
        /// Opaque report config excluding `driver_version` / `vbios_version`
        /// (those are in [`NvidiaGpuCommonClaims`]).
        config: HashMap<String, Value>,
    },
    /// Curated claims from NRAS GPU detached claims (v3.0) after built-in verify.
    ///
    /// Only policy-variable fields are retained; fixed pass/fail checks are
    /// enforced inside the verifier.
    Remote {
        #[serde(flatten)]
        common: NvidiaGpuCommonClaims,

        /// GPU hardware model.
        #[serde(skip_serializing_if = "Option::is_none")]
        hwmodel: Option<String>,

        /// Universal Entity Id.
        #[serde(skip_serializing_if = "Option::is_none")]
        ueid: Option<String>,

        /// Firmware manufacturer id.
        #[serde(skip_serializing_if = "Option::is_none")]
        oemid: Option<String>,

        /// EAT token issuer.
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,

        /// Unique physical data interfaces from GPUs to NVSwitches (optional).
        #[serde(
            rename = "x-nvidia-gpu-switch-pdis",
            skip_serializing_if = "Option::is_none"
        )]
        switch_pdis: Option<Vec<String>>,

        /// EAT nonce.
        #[serde(skip_serializing_if = "Option::is_none")]
        eat_nonce: Option<String>,
    },
}

impl From<NvDeviceReportAndCertClaim> for NvidiaGpuEvidenceClaims {
    fn from(mut c: NvDeviceReportAndCertClaim) -> Self {
        let driver_version = take_string_claim(&mut c.config, "driver_version");
        let vbios_version = take_string_claim(&mut c.config, "vbios_version");

        Self::Local {
            common: NvidiaGpuCommonClaims {
                driver_version,
                vbios_version,
            },
            arch: c.arch,
            uuid: c.uuid,
            measurements: c.measurements,
            config: c.config,
        }
    }
}

fn take_string_claim(map: &mut HashMap<String, Value>, key: &str) -> Option<String> {
    match map.remove(key)? {
        Value::String(s) => Some(s),
        other => {
            // Preserve unexpected types in config rather than dropping them.
            map.insert(key.to_string(), other);
            None
        }
    }
}

/// nvSwitch evidence claims
#[derive(Debug, Serialize)]
#[serde(tag = "verifier", rename_all = "lowercase")]
pub enum NvidiaSwitchEvidenceClaims {
    /// Curated claims from NRAS nvSwitch detached claims (v3.0) after built-in verify.
    ///
    /// Only policy-variable fields are retained; fixed pass/fail checks are
    /// enforced inside the verifier.
    Remote {
        /// Switch BIOS version (e.g. `96.00.9F.00.01`).
        #[serde(
            rename = "x-nvidia-switch-bios-version",
            skip_serializing_if = "Option::is_none"
        )]
        bios_version: Option<String>,

        /// Switch hardware model.
        #[serde(skip_serializing_if = "Option::is_none")]
        hwmodel: Option<String>,

        /// Universal Entity Id.
        #[serde(skip_serializing_if = "Option::is_none")]
        ueid: Option<String>,

        /// Firmware manufacturer id.
        #[serde(skip_serializing_if = "Option::is_none")]
        oemid: Option<String>,

        /// EAT token issuer.
        #[serde(skip_serializing_if = "Option::is_none")]
        iss: Option<String>,

        /// NVSwitch physical data interface ID (optional).
        #[serde(
            rename = "x-nvidia-switch-pdi",
            skip_serializing_if = "Option::is_none"
        )]
        switch_pdi: Option<String>,

        /// Unique physical data interfaces from NVSwitches to GPUs (optional).
        #[serde(
            rename = "x-nvidia-switch-gpu-pdis",
            skip_serializing_if = "Option::is_none"
        )]
        switch_gpu_pdis: Option<Vec<String>>,

        /// EAT nonce.
        #[serde(skip_serializing_if = "Option::is_none")]
        eat_nonce: Option<String>,
    },
}
