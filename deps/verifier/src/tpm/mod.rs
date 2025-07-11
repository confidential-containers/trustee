// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use log::debug;
use anyhow::*;
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine};
use rsa::traits::SignatureScheme;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use serde::Deserialize;
use serde_json::json;
use sha2::Digest;
use sha2::Sha256;
use tss_esapi::structures::{Attest, Public,Signature as TpmSignature};
use tss_esapi::traits::UnMarshall;

use super::*;

#[derive(Deserialize, Debug)]
pub struct Evidence {
    pub svn: String,
    pub report_data: String,
    pub tpm_quote: TpmQuote,
    pub ak_public: String,
}

#[derive(Deserialize, Debug)]
pub struct TpmQuote {
    pub signature: String,
    pub message: String,
    pub pcrs: Vec<String>,
}

#[derive(Debug, Default)]
pub struct TpmVerifier;

#[async_trait]
impl Verifier for TpmVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let ev = serde_json::from_value::<Evidence>(evidence)
            .context("Deserialize TPM Evidence failed.")?;
        let tpm_quote = &ev.tpm_quote;

        // 1. Verify the quote signature using AK pubkey
        verify_tpm_quote_signature(tpm_quote, &ev.ak_public)?;

        // Verify the nonce matches expected report_data
        if let ReportData::Value(expected_report_data) = expected_report_data {
            let nonce = base64::engine::general_purpose::STANDARD
                .decode(&ev.report_data)
                .context("base64 decode report_data for TPM evidence")?;
            if *expected_report_data != nonce {
                bail!("TPM quote nonce doesn't match expected report_data");
            }
        }

        // Optionally, verify PCRs (e.g., PCR[8] for init_data_hash)
        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            if tpm_quote.pcrs.len() > 8 {
                let pcr8 = base64::engine::general_purpose::STANDARD
                    .decode(&tpm_quote.pcrs[8])
                    .context("base64 decode PCR[8] for TPM evidence")?;
                if *expected_init_data_hash != pcr8 {
                    bail!("TPM PCR[8] doesn't match expected init_data_hash");
                }
            }
        }

        debug!("TPM Evidence: {:?}", tpm_quote);
        let claims = parse_tpm_evidence(&ev)?;
        Ok((claims, "cpu".to_string()))
    }
}

pub fn verify_tpm_quote_signature(tpm_quote: &TpmQuote, ak_public: &String) -> Result<()> {
    let sig_bytes = general_purpose::STANDARD
        .decode(&tpm_quote.signature)
        .context("Base64 decode of TPM quote signature failed")?;

    let pub_bytes = general_purpose::STANDARD
        .decode(ak_public)
        .context("Base64 decode of AK public failed")?;

    let quote_bytes = general_purpose::STANDARD
        .decode(&tpm_quote.message)
        .context("Base64 decode of quote message failed")?;

    let _attest = Attest::unmarshall(&quote_bytes)?;
    let ak = Public::unmarshall(&pub_bytes)?;
    let signature = TpmSignature::unmarshall(&sig_bytes)?;
    let TpmSignature::RsaSsa(_) = signature.clone() else {
        bail!("Wrong Signature");
    };

    let rsa_public = match ak {
        Public::Rsa {
            ref unique,
            ref parameters,
            ..
        } => {
            let n = rsa::BigUint::from_bytes_be(unique.value());
            let e = parameters.exponent().value();
            let e = if e == 0 { 65537 } else { e }; // 0 means default 65537 in TPM
            let e = rsa::BigUint::from(e);

            RsaPublicKey::new(n, e).context("Failed to construct RSA public key")?
        }
        _ => anyhow::bail!("Unsupported AK key type"),
    };
    // Extract raw RSA signature from the TPM signature in TPM marshalled format, which includes a 6-byte header.
    if sig_bytes.len() < 6 {
        bail!("signature is too short");
    }
    let sig_bytes = &sig_bytes[6..];
    let hashed = Sha256::digest(&quote_bytes);

    let verifier = Pkcs1v15Sign::new::<Sha256>();
    verifier
        .verify(&rsa_public, &hashed, sig_bytes)
        .context("RSA signature verification failed")?;

    debug!("TPM quote signature is valid.");

    Ok(())
}

pub fn parse_tpm_evidence(ev: &Evidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": ev.svn,
        "report_data": ev.report_data,        
        "message": ev.tpm_quote.message,
        "pcrs": ev.tpm_quote.pcrs,
    });
    Ok(claims_map as TeeEvidenceParsedClaim)
}
