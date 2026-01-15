// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Compatibility layer for legacy (v0) evidence format conversion.

use super::super::az_snp_vtpm::TpmQuote;
use anyhow::Result;
use az_tdx_vtpm::vtpm::Quote;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::serde_as;

/// Legacy evidence format (v0) - no version field, uses bincode-serialized Quote
#[derive(Serialize, Deserialize)]
pub(super) struct EvidenceV0 {
    pub(super) tpm_quote: Quote,
    pub(super) hcl_report: Vec<u8>,
    pub(super) td_quote: Vec<u8>,
}

/// Attestation evidence for Azure TDX vTPM (v1).
#[serde_as]
#[derive(Serialize, Deserialize)]
pub(super) struct EvidenceV1 {
    pub(super) version: u32,
    pub(super) tpm_quote: TpmQuote,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) hcl_report: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) td_quote: Vec<u8>,
}

/// Versioned evidence wrapper - tries V1 first, falls back to V0
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Evidence {
    V1(EvidenceV1),
    V0(EvidenceV0),
}

impl Evidence {
    pub(super) fn hcl_report(&self) -> &[u8] {
        match self {
            Evidence::V0(v0) => &v0.hcl_report,
            Evidence::V1(v1) => &v1.hcl_report,
        }
    }

    pub(super) fn td_quote(&self) -> &[u8] {
        match self {
            Evidence::V0(v0) => &v0.td_quote,
            Evidence::V1(v1) => &v1.td_quote,
        }
    }

    pub(super) fn tpm_quote(&self) -> Result<TpmQuote> {
        match self {
            Evidence::V0(v0) => {
                let tpm_quote: TpmQuote = v0.tpm_quote.clone().try_into()?;
                Ok(tpm_quote)
            }
            Evidence::V1(v1) => Ok(v1.tpm_quote.clone()),
        }
    }
}
