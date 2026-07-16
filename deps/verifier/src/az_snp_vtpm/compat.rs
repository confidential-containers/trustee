// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Compatibility layer for legacy (v0) evidence format conversion.

use anyhow::{Context, Result};
use az_snp_vtpm::vtpm::Quote;
use openssl::x509::X509;
use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::hex::Hex;
use serde_with::serde_as;
use std::convert::From;

// Validation helper to assert evidence versions
#[derive(Debug)]
pub(crate) struct VersionCheck<const V: u32>;

impl<'a, const V: u32> Deserialize<'a> for VersionCheck<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'a>,
    {
        let val = u32::deserialize(deserializer)?;
        if val != V {
            return Err(SerdeError::custom(format!("Expected version {}", V)));
        }
        Ok(VersionCheck)
    }
}

/// Legacy evidence format (v0) - no version field
#[derive(Serialize, Deserialize)]
pub(super) struct EvidenceV0 {
    pub(super) quote: Quote,
    pub(super) report: Vec<u8>,
    pub(super) vcek: String,
}

/// Attestation evidence for Azure SNP vTPM (v1).
#[serde_as]
#[derive(Deserialize)]
pub(super) struct EvidenceV1 {
    #[serde(rename = "version")]
    _version: VersionCheck<1>,
    pub(super) tpm_quote: TpmQuote,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) hcl_report: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) vcek: Vec<u8>,
}

/// Attestation evidence for Azure SNP vTPM (v2).
///
/// V2 is structurally the same as v1, but will have the user-data field in
/// HCL variable-data populated with report_data
#[serde_as]
#[derive(Deserialize)]
pub(super) struct EvidenceV2 {
    #[serde(rename = "version")]
    _version: VersionCheck<2>,
    pub(super) tpm_quote: TpmQuote,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) hcl_report: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) vcek: Vec<u8>,
}

/// Versioned evidence wrapper - tries V1 first, falls back to V0
#[derive(Deserialize)]
#[serde(untagged)]
pub(super) enum Evidence {
    V2(EvidenceV2),
    V1(EvidenceV1),
    V0(EvidenceV0),
}

/// TPM quote containing PCR values and attestation data.
#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub(crate) struct TpmQuote {
    #[serde_as(as = "Hex")]
    pub(crate) signature: Vec<u8>,
    #[serde_as(as = "Hex")]
    pub(crate) message: Vec<u8>,
    #[serde_as(as = "Vec<Hex>")]
    pub(crate) pcrs: Vec<Vec<u8>>,
}

impl From<Quote> for TpmQuote {
    fn from(quote: Quote) -> Self {
        let pcrs = quote.pcrs_sha256().map(|p| p.to_vec()).collect();

        TpmQuote {
            signature: quote.signature(),
            message: quote.message(),
            pcrs,
        }
    }
}

pub(super) enum Vcek {
    Pem(X509),
    Der(Vec<u8>),
}

impl Evidence {
    pub(super) fn hcl_report(&self) -> &[u8] {
        match self {
            Evidence::V0(v0) => &v0.report,
            Evidence::V1(v1) => &v1.hcl_report,
            Evidence::V2(v2) => &v2.hcl_report,
        }
    }

    pub(super) fn tpm_quote(&self) -> TpmQuote {
        match self {
            Evidence::V0(v0) => v0.quote.clone().into(),
            Evidence::V1(v1) => v1.tpm_quote.clone(),
            Evidence::V2(v2) => v2.tpm_quote.clone(),
        }
    }

    pub(super) fn vcek(&self) -> Result<Vcek> {
        match self {
            Evidence::V0(v0) => {
                let vcek_pem = v0.vcek.as_bytes();
                let vcek_x509 = X509::from_pem(vcek_pem).context("Invalid VCEK PEM")?;
                Ok(Vcek::Pem(vcek_x509))
            }
            Evidence::V1(v1) => Ok(Vcek::Der(v1.vcek.clone())),
            Evidence::V2(v2) => Ok(Vcek::Der(v2.vcek.clone())),
        }
    }

    pub(super) fn version(&self) -> u32 {
        match self {
            Evidence::V0(_) => 0,
            Evidence::V1(_) => 1,
            Evidence::V2(_) => 2,
        }
    }
}
