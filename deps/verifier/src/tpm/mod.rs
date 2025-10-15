// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use az_cvm_vtpm::vtpm::Quote as VtpmQuote;
use base64::{engine::general_purpose, Engine};
use hex;
use log::{debug, info};
use openssl::pkey::PKey;
use serde::Deserialize;
use serde_json::{self, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs;
use std::result::Result::Ok;
use tss_esapi::structures::Signature;
use tss_esapi::traits::UnMarshall;

use super::*;
pub mod config;

const MAX_TRUSTED_AK_KEYS: usize = 100;
const DEFAULT_TRUSTED_AK_KEYS_DIR: &str = "/etc/tpm/trusted_ak_keys";
const INITDATA_PCR: usize = 8;
const TPM_REPORT_DATA_SIZE: usize = 64;

// TPM evidence format as sent by the TPM attester
#[derive(Deserialize, Debug)]
pub struct Evidence {
    pub ak_public: String,
    pub tpm_quote: Quote,
}

// The TPM quote with string-encoded fields for JSON serialization
#[derive(Deserialize, Debug)]
pub struct Quote {
    pub signature: String, // base64 encoded
    pub message: String,   // base64 encoded
    pub pcrs: Vec<String>, // hex-encoded strings
}

impl Quote {
    fn to_quote(&self) -> Result<VtpmQuote> {
        // Extract raw signature bytes from the marshalled TSS signature
        // Attester marshals the entire Signature struct, but az_cvm_vtpm expects raw bytes
        let raw_signature_bytes = self.extract_raw_signature_bytes()?;

        // Decode the attestation message
        let message = general_purpose::STANDARD
            .decode(&self.message)
            .context("Failed to decode message from base64")?;

        // Parse PCR values from hex strings to byte arrays
        let pcrs = self.parse_pcr_values()?;

        // Construct Quote with the corrected signature format
        let quote_data = serde_json::json!({
            "signature": raw_signature_bytes,
            "message": message,
            "pcrs": pcrs
        });

        serde_json::from_value::<VtpmQuote>(quote_data)
            .context("Failed to construct Quote from parsed data")
    }

    fn extract_raw_signature_bytes(&self) -> Result<Vec<u8>> {
        let signature_marshalled = general_purpose::STANDARD
            .decode(&self.signature)
            .context("Failed to decode signature from base64")?;

        let tss_signature = Signature::unmarshall(&signature_marshalled)
            .context("Failed to unmarshal TSS signature")?;

        match tss_signature {
            Signature::RsaSsa(rsa_sig) => Ok(rsa_sig.signature().to_vec()),
            _ => bail!("Unsupported signature type, expected RSA-SSA"),
        }
    }

    fn parse_pcr_values(&self) -> Result<Vec<[u8; 32]>> {
        let mut pcrs = Vec::new();
        for pcr_str in &self.pcrs {
            if pcr_str.len() != 64 {
                bail!(
                    "PCR should be 64 hex characters (32 bytes), got {}",
                    pcr_str.len()
                );
            }
            let pcr_bytes = hex::decode(pcr_str)
                .with_context(|| format!("Failed to decode PCR from hex: {}", pcr_str))?;
            if pcr_bytes.len() != 32 {
                bail!("PCR should be exactly 32 bytes, got {}", pcr_bytes.len());
            }
            let pcr_array: [u8; 32] = pcr_bytes
                .try_into()
                .map_err(|_| anyhow!("PCR must be exactly 32 bytes"))?;
            pcrs.push(pcr_array);
        }
        Ok(pcrs)
    }
}

#[derive(Debug)]
pub struct TpmVerifier {
    trusted_ak_hashes: HashSet<Vec<u8>>,
}

impl Default for TpmVerifier {
    fn default() -> Self {
        let config = config::TpmVerifierConfig::default();
        Self::new(Some(config)).unwrap_or_else(|_| Self {
            trusted_ak_hashes: HashSet::new(),
        })
    }
}

impl TpmVerifier {
    /// Load a public key from a file and return its SHA256 hash
    fn load_and_hash_key(path: &std::path::Path) -> Result<Vec<u8>> {
        let key_content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read key file: {:?}", path))?;
        let pkey = PKey::public_key_from_pem(key_content.as_bytes())
            .with_context(|| format!("Failed to parse PEM public key from: {:?}", path))?;
        let key_bytes = pkey
            .public_key_to_der()
            .with_context(|| format!("Failed to convert PEM to DER for: {:?}", path))?;
        let hash = Sha256::digest(&key_bytes).to_vec();
        Ok(hash)
    }

    pub fn new(config: Option<config::TpmVerifierConfig>) -> Result<Self> {
        let config = config.unwrap_or_default();
        let mut trusted_ak_hashes = HashSet::new();

        let keys_dir = config.trusted_ak_keys_dir;

        info!("TPM verifier trusted keys dir {:?}", keys_dir);

        // Build a lazy iterator to filter and take valid .pub files
        // without collecting them into a vector first

        let dir_entries = fs::read_dir(&keys_dir)
            .with_context(|| format!("Failed to read trusted AK keys directory {:?}", keys_dir))?;

        let trusted_keys = dir_entries
            .filter_map(|entry_result| entry_result.ok())
            .filter(|entry| {
                let path = entry.path();
                path.is_file() && path.extension() == Some("pub".as_ref())
                // This implicitly filters out '.' and '..'
            })
            // The directory will not be read beyond this number of valid files
            .take(config.max_trusted_ak_keys);

        for entry in trusted_keys {
            let path = entry.path();

            // Try to read and parse the key, but continue on error instead of failing
            match Self::load_and_hash_key(&path) {
                Ok(hash) => {
                    debug!("Successfully loaded trusted AK key from {:?}", path);
                    trusted_ak_hashes.insert(hash);
                }
                Err(e) => {
                    log::warn!("Failed to load trusted AK key from {:?}: {}", path, e);
                    continue;
                }
            }
        }

        info!(
            "TPM verifier loaded {} trusted AK key(s)",
            trusted_ak_hashes.len()
        );
        Ok(Self { trusted_ak_hashes })
    }
}

fn verify_signature(quote: &VtpmQuote, ak_public: &str) -> Result<()> {
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

fn verify_pcrs(quote: &VtpmQuote) -> Result<()> {
    quote
        .verify_pcrs()
        .context("Digest of PCRs does not match digest in Quote")?;
    debug!("PCR verification completed successfully");
    Ok(())
}

fn verify_nonce(quote: &VtpmQuote, expected_report_data: &[u8]) -> Result<()> {
    let nonce = quote.nonce()?;

    debug!(
        "Expected report_data ({} bytes): {}",
        expected_report_data.len(),
        hex::encode(expected_report_data)
    );
    debug!(
        "Quote nonce ({} bytes): {}",
        nonce.len(),
        hex::encode(&nonce)
    );

    // TPM attester pads report_data to 64 bytes, so we need to pad expected_report_data the same way
    let mut padded_expected = expected_report_data.to_vec();
    padded_expected.resize(TPM_REPORT_DATA_SIZE, 0);

    if nonce == padded_expected {
        debug!("TPM report_data verification completed successfully");
        Ok(())
    } else {
        debug!("Nonce and padded expected are different");
        bail!("TPM quote nonce doesn't match expected report_data")
    }
}

fn verify_init_data(expected: &InitDataHash, quote: &VtpmQuote) -> Result<()> {
    match expected {
        InitDataHash::Value(expected_init_data_hash) => {
            debug!("Check the binding of PCR{INITDATA_PCR}");

            // sha256(0x00 * 32 || expected_init_data_hash)
            let mut input = [0u8; 64];
            input[32..].copy_from_slice(expected_init_data_hash);
            let digest = openssl::sha::sha256(&input);

            let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
            let init_data_pcr = pcrs[INITDATA_PCR];
            if &digest == init_data_pcr {
                Ok(())
            } else {
                bail!(format!(
                    "TPM PCR[{INITDATA_PCR}] doesn't match expected initdata hash"
                ))
            }
        }
        InitDataHash::NotProvided => {
            debug!("No expected value, skipping init_data verification");
            Ok(())
        }
    }
}

fn extend_claim(claim: &mut TeeEvidenceParsedClaim, quote: &VtpmQuote) -> Result<()> {
    let serde_json::Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
    for (i, pcr) in pcrs.iter().enumerate() {
        map.insert(
            format!("pcr{:02}", i),
            serde_json::Value::String(hex::encode(pcr)),
        );
    }
    Ok(())
}

#[async_trait]
impl Verifier for TpmVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let guest_ev = serde_json::from_value::<Evidence>(evidence)
            .context("Failed to deserialize TPM Evidence")?;

        let quote = guest_ev
            .tpm_quote
            .to_quote()
            .context("Failed to convert quote from string format")?;

        let ak_public = guest_ev.ak_public;

        // 1. Check if the provided AK public key is trusted
        let ak_public_bytes = general_purpose::STANDARD.decode(&ak_public)?;
        let ak_public_hash = Sha256::digest(&ak_public_bytes).to_vec();

        if !self.trusted_ak_hashes.contains(&ak_public_hash) {
            bail!("The provided AK public key is not in the list of trusted keys");
        }

        // 2. Verify the quote signature using the (now trusted) AK pubkey
        verify_signature(&quote, &ak_public)?;

        // 3. Verify PCRs
        verify_pcrs(&quote)?;

        // 4. Verify nonce/report data
        if let ReportData::Value(report_data) = expected_report_data {
            verify_nonce(&quote, report_data)?;
        }

        // 5. Verify init data hash
        verify_init_data(expected_init_data_hash, &quote)?;

        // 6. Parse claims
        let mut claims = parse_tee_evidence(&quote);
        extend_claim(&mut claims, &quote)?;

        Ok(vec![(claims, "cpu".to_string())])
    }
}

pub fn parse_tee_evidence(quote: &VtpmQuote) -> TeeEvidenceParsedClaim {
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
    use std::path::PathBuf;

    const TPM_EVIDENCE: &[u8] = include_bytes!("../../test_data/tpm_evidence.json");

    #[test]
    fn test_tpm_verifier_nonexistent_keys_dir() {
        // When trusted_ak_keys_dir points to a nonexistent directory, verifier initialization should fail
        let config = config::TpmVerifierConfig {
            trusted_ak_keys_dir: PathBuf::from("/nonexistent/directory/for/testing"),
            max_trusted_ak_keys: MAX_TRUSTED_AK_KEYS,
        };
        let result = TpmVerifier::new(Some(config));
        assert!(
            result.is_err(),
            "Verifier should fail to initialize with nonexistent trusted_ak_keys_dir"
        );
        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Failed to read trusted AK keys directory"),
            "Error message should mention the directory read failure, got: {}",
            error_msg
        );
    }

    #[test]
    fn test_tpm_verifier_default_config() {
        let config = config::TpmVerifierConfig::default();
        assert_eq!(config.max_trusted_ak_keys, MAX_TRUSTED_AK_KEYS);
        assert_eq!(
            config.trusted_ak_keys_dir.to_str().unwrap(),
            DEFAULT_TRUSTED_AK_KEYS_DIR,
            "Default config should have trusted_ak_keys_dir set to default path"
        );
    }

    #[test]
    fn test_tpm_verifier_custom_config() {
        let config = config::TpmVerifierConfig {
            trusted_ak_keys_dir: PathBuf::from("/custom/path"),
            max_trusted_ak_keys: 50,
        };
        assert_eq!(config.max_trusted_ak_keys, 50);
        assert_eq!(config.trusted_ak_keys_dir.to_str().unwrap(), "/custom/path");
    }

    #[test]
    fn test_deserialize_tpm_evidence_fixture() {
        // Test that we can deserialize the TPM evidence fixture
        // This ensures the fixture format is correct and won't break during refactoring
        let tpm_evidence = serde_json::from_slice::<Evidence>(TPM_EVIDENCE)
            .expect("Failed to deserialize TPM Evidence");

        // Verify the evidence has the expected structure
        assert!(
            !tpm_evidence.ak_public.is_empty(),
            "AK public key should not be empty"
        );
        assert_eq!(tpm_evidence.tpm_quote.pcrs.len(), 24, "Should have 24 PCRs");
        assert!(
            !tpm_evidence.tpm_quote.signature.is_empty(),
            "Signature should not be empty"
        );
        assert!(
            !tpm_evidence.tpm_quote.message.is_empty(),
            "Message should not be empty"
        );

        // Verify we can convert to Quote format
        let quote = tpm_evidence
            .tpm_quote
            .to_quote()
            .expect("Should be able to convert quote to internal format");

        // Verify PCRs can be accessed
        let pcrs: Vec<&[u8; 32]> = quote.pcrs_sha256().collect();
        assert_eq!(pcrs.len(), 24, "Quote should contain 24 PCRs");
    }

    #[test]
    fn test_parse_tee_evidence() {
        // Test the parse_tee_evidence function with a real quote
        let tpm_evidence = serde_json::from_slice::<Evidence>(TPM_EVIDENCE)
            .expect("Failed to deserialize TPM Evidence");

        let quote = tpm_evidence
            .tpm_quote
            .to_quote()
            .expect("Should be able to convert quote to internal format");

        let claims = parse_tee_evidence(&quote);

        // Verify claims contain expected fields
        assert!(
            claims.get("init_data").is_some(),
            "Claims should contain init_data"
        );
        assert!(
            claims.get("report_data").is_some(),
            "Claims should contain report_data"
        );

        // Verify the values are hex-encoded strings
        let init_data = claims.get("init_data").unwrap().as_str().unwrap();
        let report_data = claims.get("report_data").unwrap().as_str().unwrap();
        assert_eq!(
            init_data.len(),
            64,
            "init_data should be 64 hex chars (32 bytes)"
        );
        assert_eq!(
            report_data.len(),
            128,
            "report_data should be 128 hex chars (64 bytes)"
        );
    }
}
