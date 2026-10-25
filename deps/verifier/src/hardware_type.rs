// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Normalized `hardware_type` claim for verifier parsed evidence.
//!
//! Prefer `"hardware_type": types::...` in local `json!` builders.
//! Use [`insert`] when claims come from serde or other helpers.

use serde_json::Value;

/// Claim key for the normalized hardware platform identifier.
pub const CLAIM: &str = "hardware_type";

pub mod types {
    pub const INTEL_SGX: &str = "intel-sgx";
    pub const INTEL_TDX: &str = "intel-tdx";
    pub const AMD_SNP: &str = "amd-snp";
    pub const AZURE_SNP_VTPM: &str = "azure-snp-vtpm";
    pub const AZURE_TDX_VTPM: &str = "azure-tdx-vtpm";
    pub const ARM_CCA: &str = "arm-cca";
    pub const HYGON_CSV: &str = "hygon-csv";
    pub const HYGON_DCU: &str = "hygon-dcu";
    pub const IBM_SE: &str = "ibm-se";
    pub const TPM: &str = "tpm";
    pub const NVIDIA_HOPPER: &str = "nvidia-hopper";
    pub const NVIDIA_BLACKWELL: &str = "nvidia-blackwell";
    pub const NVIDIA_LS10: &str = "nvidia-ls10";
    pub const NVIDIA_PPCIE: &str = "nvidia-ppcie";
    pub const NVIDIA_DPU: &str = "nvidia-dpu";
    pub const SAMPLE: &str = "sample";
    pub const SAMPLE_DEVICE: &str = "sample-device";
}

/// Insert `hardware_type` into claims assembled outside a local `json!` builder.
pub fn insert(claims: &mut Value, hardware_type: &str) {
    if let Some(obj) = claims.as_object_mut() {
        obj.insert(
            CLAIM.to_string(),
            Value::String(hardware_type.to_string()),
        );
    }
}
