// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Compatibility layer for legacy (v0) evidence format conversion.

use anyhow::{Context, Result};
use az_snp_vtpm::vtpm::Quote;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_with::base64::{Base64, UrlSafe};
use serde_with::hex::Hex;
use serde_with::serde_as;
use std::convert::TryFrom;

/// Legacy evidence format (v0) - no version field
#[derive(Serialize, Deserialize)]
pub(super) struct EvidenceV0 {
    pub(super) quote: Quote,
    pub(super) report: Vec<u8>,
    pub(super) vcek: String,
}

/// Attestation evidence for Azure SNP vTPM (v1).
#[serde_as]
#[derive(Serialize, Deserialize)]
pub(super) struct EvidenceV1 {
    pub(super) version: u32,
    pub(super) tpm_quote: TpmQuote,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) hcl_report: Vec<u8>,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub(super) vcek: Vec<u8>,
}

/// Versioned evidence wrapper - tries V1 first, falls back to V0
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum Evidence {
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

/// Helper struct to extract Quote fields via serde (fields are private in Quote)
#[derive(Deserialize)]
struct QuoteFields {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcrs: Vec<[u8; 32]>,
}

impl TryFrom<Quote> for TpmQuote {
    type Error = anyhow::Error;
    fn try_from(quote: Quote) -> Result<Self> {
        let quote_json = serde_json::to_value(&quote)?;
        let fields: QuoteFields = serde_json::from_value(quote_json)?;

        Ok(TpmQuote {
            signature: fields.signature,
            message: fields.message,
            pcrs: fields.pcrs.into_iter().map(|p| p.to_vec()).collect(),
        })
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
        }
    }

    pub(super) fn tpm_quote(&self) -> Result<TpmQuote> {
        match self {
            Evidence::V0(v0) => {
                let tpm_quote: TpmQuote = v0.quote.clone().try_into()?;
                Ok(tpm_quote)
            }
            Evidence::V1(v1) => Ok(v1.tpm_quote.clone()),
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
        }
    }
}
