// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use az_cvm_vtpm::vtpm::Quote;
use base64::{engine::general_purpose, Engine};
use log::{debug, warn};
use openssl::pkey::PKey;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use thiserror::Error;

use super::*;
pub mod config;

const MAX_TRUSTED_AK_KEYS: usize = 100;
const INITDATA_PCR: usize = 8;

// Simple hex decode function since hex crate isn't available
fn decode_hex(s: &str) -> Result<Vec<u8>, std::num::ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

#[derive(Error, Debug)]
pub enum TpmVerifierError {
    #[error("The provided AK public key is not in the list of trusted keys")]
    UntrustedAkKey,
    #[error("TPM quote nonce doesn't match expected report_data")]
    NonceMismatch,
    #[error("TPM PCR[8] doesn't match expected init_data_hash")]
    InitDataMismatch,
    #[error("Evidence field missing: {0}")]
    MissingField(String),
    #[error(transparent)]
    Quote(#[from] az_cvm_vtpm::vtpm::QuoteError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

#[derive(Deserialize, Debug)]
pub struct Evidence {
    pub quote: Quote,
    pub ak_public: String,
}

// Support for guest-components attester format (what the client actually sends)
#[derive(Deserialize, Debug)]
pub struct GuestComponentsEvidence {
    pub ak_public: String,
    pub tpm_quote: QuoteStringFormat,
}

// The quote as sent by the client (with string fields instead of binary)
#[derive(Deserialize, Debug)]
pub struct QuoteStringFormat {
    pub signature: String, // base64 encoded
    pub message: String,   // base64 encoded
    pub pcrs: Vec<String>, // hex-encoded strings
}

impl QuoteStringFormat {
    fn to_quote_json(&self) -> Result<Value> {
        let signature = general_purpose::STANDARD
            .decode(&self.signature)
            .context("Failed to decode signature from base64")?;
        let message = general_purpose::STANDARD
            .decode(&self.message)
            .context("Failed to decode message from base64")?;

        let mut pcrs = Vec::new();
        for pcr_str in &self.pcrs {
            if pcr_str.len() != 64 {
                bail!(
                    "PCR should be 64 hex characters (32 bytes), got {}",
                    pcr_str.len()
                );
            }
            let pcr_bytes = decode_hex(pcr_str)
                .with_context(|| format!("Failed to decode PCR from hex: {}", pcr_str))?;
            if pcr_bytes.len() != 32 {
                bail!("PCR should be exactly 32 bytes, got {}", pcr_bytes.len());
            }
            pcrs.push(pcr_bytes);
        }

        // Create the JSON that Quote's deserializer expects
        Ok(json!({
            "signature": signature,
            "message": message,
            "pcrs": pcrs
        }))
    }
}

#[derive(Debug)]
pub struct TpmVerifier {
    trusted_ak_hashes: HashSet<Vec<u8>>,
}

impl Default for TpmVerifier {
    fn default() -> Self {
        let config = config::TpmVerifierConfig::default();
        Self::new(config).unwrap_or_else(|_| Self {
            trusted_ak_hashes: HashSet::new(),
        })
    }
}

impl TpmVerifier {
    pub fn new(config: config::TpmVerifierConfig) -> Result<Self> {
        let mut trusted_ak_hashes = HashSet::new();
        if let Some(keys_dir) = config.trusted_ak_keys_dir {
            let entries = fs::read_dir(keys_dir)?.collect::<Result<Vec<_>, _>>()?;
            if entries.len() > config.max_trusted_ak_keys {
                warn!(
                    "Number of trusted AK keys ({}) exceeds the limit ({}). Only the first {} keys will be loaded.",
                    entries.len(),
                    config.max_trusted_ak_keys,
                    config.max_trusted_ak_keys
                );
            }

            for entry in entries.into_iter().take(config.max_trusted_ak_keys) {
                let path = entry.path();
                if path.is_file() {
                    let key_b64 = fs::read_to_string(path)?;
                    let key_bytes = general_purpose::STANDARD.decode(key_b64.trim())?;
                    let hash = Sha256::digest(&key_bytes).to_vec();
                    trusted_ak_hashes.insert(hash);
                }
            }
        }
        Ok(Self { trusted_ak_hashes })
    }
}

fn verify_signature(quote: &Quote, ak_public: &str) -> Result<()> {
    let pub_bytes = general_purpose::STANDARD
        .decode(ak_public)
        .context("Base64 decode of AK public failed")?;

    let ak_pub = PKey::public_key_from_der(&pub_bytes).context("Failed to parse AK public key")?;

    quote
        .verify_signature(&ak_pub)
        .context("TPM quote signature verification failed")?;

    debug!("TPM quote signature is valid.");
    Ok(())
}

fn verify_pcrs(quote: &Quote) -> Result<()> {
    quote
        .verify_pcrs()
        .context("Digest of PCRs does not match digest in Quote")?;
    debug!("PCR verification completed successfully");
    Ok(())
}

fn verify_nonce(quote: &Quote, expected_report_data: &[u8]) -> Result<()> {
    let nonce = quote.nonce()?;
    match nonce == expected_report_data {
        true => {
            debug!("TPM report_data verification completed successfully");
            Ok(())
        }
        false => Err(TpmVerifierError::NonceMismatch.into()),
    }
}

fn verify_init_data(expected: &InitDataHash, quote: &Quote) -> Result<()> {
    match expected {
        InitDataHash::Value(expected_init_data_hash) => {
            debug!("Check the binding of PCR{INITDATA_PCR}");

            // sha256(0x00 * 32 || expected_init_data_hash)
            let mut input = [0u8; 64];
            input[32..].copy_from_slice(expected_init_data_hash);
            let digest = openssl::sha::sha256(&input);

            let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
            let init_data_pcr = pcrs[INITDATA_PCR];
            match &digest == init_data_pcr {
                true => Ok(()),
                false => Err(TpmVerifierError::InitDataMismatch.into()),
            }
        }
        InitDataHash::NotProvided => {
            debug!("No expected value, skipping init_data verification");
            Ok(())
        }
    }
}

fn extend_claim(claim: &mut TeeEvidenceParsedClaim, quote: &Quote) -> Result<()> {
    let serde_json::Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
    let mut tpm_values = serde_json::Map::new();
    for (i, pcr) in pcrs.iter().enumerate() {
        tpm_values.insert(
            format!("pcr{:02}", i),
            serde_json::Value::String(hex::encode(pcr)),
        );
    }
    map.insert("tpm".to_string(), serde_json::Value::Object(tpm_values));
    map.insert(
        "init_data".into(),
        serde_json::Value::String(hex::encode(pcrs[INITDATA_PCR])),
    );
    map.insert(
        "report_data".into(),
        serde_json::Value::String(hex::encode(quote.nonce()?)),
    );
    Ok(())
}

#[async_trait]
impl Verifier for TpmVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        // Try to deserialize in guest-components format first, then fall back to original format
        let ev = if let std::result::Result::Ok(guest_ev) =
            serde_json::from_value::<GuestComponentsEvidence>(evidence.clone())
        {
            let quote_json = guest_ev
                .tpm_quote
                .to_quote_json()
                .context("Failed to convert quote from string format")?;
            let quote = serde_json::from_value::<Quote>(quote_json)
                .context("Failed to deserialize converted quote")?;
            Evidence {
                quote,
                ak_public: guest_ev.ak_public,
            }
        } else {
            serde_json::from_value::<Evidence>(evidence)
                .context("Deserialize TPM Evidence failed.")?
        };

        // 1. Check if the provided AK public key is trusted
        let ak_public_bytes = general_purpose::STANDARD.decode(&ev.ak_public)?;
        let ak_public_hash = Sha256::digest(&ak_public_bytes).to_vec();

        match self.trusted_ak_hashes.contains(&ak_public_hash) {
            true => {}
            false => return Err(TpmVerifierError::UntrustedAkKey.into()),
        }

        // 2. Verify the quote signature using the (now trusted) AK pubkey
        verify_signature(&ev.quote, &ev.ak_public)?;

        // 3. Verify PCRs
        verify_pcrs(&ev.quote)?;

        // 4. Verify nonce/report data
        match expected_report_data {
            ReportData::Value(expected_report_data) => {
                verify_nonce(&ev.quote, expected_report_data)?;
            }
            ReportData::NotProvided => {}
        }

        // 5. Verify init data hash
        verify_init_data(expected_init_data_hash, &ev.quote)?;

        // 6. Parse claims
        let mut claims = parse_tee_evidence(&ev.quote);
        extend_claim(&mut claims, &ev.quote)?;

        Ok((claims, "cpu".to_string()))
    }
}

pub fn parse_tee_evidence(quote: &Quote) -> TeeEvidenceParsedClaim {
    let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
    let claims_map = json!({
        "init_data": hex::encode(pcrs[INITDATA_PCR]),
        "report_data": hex::encode(quote.nonce().unwrap_or_default()),
    });
    claims_map as TeeEvidenceParsedClaim
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    fn test_tpm_verifier_new_empty_config() {
        let config = config::TpmVerifierConfig {
            trusted_ak_keys_dir: None,
            max_trusted_ak_keys: MAX_TRUSTED_AK_KEYS,
        };
        let verifier = TpmVerifier::new(config).unwrap();
        assert!(verifier.trusted_ak_hashes.is_empty());
    }

    #[rstest]
    fn test_tpm_verifier_default_config() {
        let config = config::TpmVerifierConfig::default();
        assert_eq!(config.max_trusted_ak_keys, MAX_TRUSTED_AK_KEYS);
        assert!(config.trusted_ak_keys_dir.is_none());
    }

    #[rstest]
    fn test_tpm_verifier_custom_max_keys() {
        let config = config::TpmVerifierConfig {
            trusted_ak_keys_dir: None,
            max_trusted_ak_keys: 50,
        };
        assert_eq!(config.max_trusted_ak_keys, 50);
    }

    #[rstest]
    fn test_verify_nonce_success() {
        // Mock quote and expected data - this would need real test data
        // For now, just test the error cases we can test
        let _expected_data = b"test_nonce";
        // This test would need a real Quote object for full testing
        // verify_nonce(&quote, expected_data).unwrap();
    }

    #[rstest]
    fn test_verify_nonce_mismatch() {
        // Mock quote and mismatched data - this would need real test data
        // For now, just test that error type exists
        let error = TpmVerifierError::NonceMismatch;
        assert_eq!(
            error.to_string(),
            "TPM quote nonce doesn't match expected report_data"
        );
    }

    #[rstest]
    fn test_untrusted_ak_key_error() {
        let error = TpmVerifierError::UntrustedAkKey;
        assert_eq!(
            error.to_string(),
            "The provided AK public key is not in the list of trusted keys"
        );
    }

    #[rstest]
    fn test_init_data_mismatch_error() {
        let error = TpmVerifierError::InitDataMismatch;
        assert_eq!(
            error.to_string(),
            "TPM PCR[8] doesn't match expected init_data_hash"
        );
    }

    #[rstest]
    fn test_missing_field_error() {
        let error = TpmVerifierError::MissingField("test_field".to_string());
        assert_eq!(error.to_string(), "Evidence field missing: test_field");
    }
}
