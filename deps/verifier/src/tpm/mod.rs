// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use az_cvm_vtpm::vtpm::Quote;
use base64::{engine::general_purpose, Engine};
use hex;
use log::{debug, info};
use openssl::pkey::PKey;
use serde::Deserialize;
use serde_json::{self, json};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::result::Result::Ok;
use std::fs;
use tss_esapi::structures::Signature;
use tss_esapi::traits::UnMarshall;

use super::*;
pub mod config;

const MAX_TRUSTED_AK_KEYS: usize = 100;
const INITDATA_PCR: usize = 8;
const TPM_REPORT_DATA_SIZE: usize = 64;

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
    fn to_quote(&self) -> Result<Quote> {
        // Extract raw signature bytes from the marshalled TSS signature
        // Guest-components marshals the entire Signature struct, but az_cvm_vtpm expects raw bytes
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

        serde_json::from_value::<Quote>(quote_data)
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
            let pcr_array: [u8; 32] = pcr_bytes.try_into()
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
        Self::new(config).unwrap_or_else(|_| Self {
            trusted_ak_hashes: HashSet::new(),
        })
    }
}

impl TpmVerifier {
    pub fn new(config: config::TpmVerifierConfig) -> Result<Self> {
        let mut trusted_ak_hashes = HashSet::new();

        let Some(keys_dir) = config.trusted_ak_keys_dir else {
            return Ok(Self { trusted_ak_hashes });
        };

        info!("TPM verifier trusted keys dir {:?}", keys_dir);

        // Build a lazy iterator to filter and take valid .pub files
        // without collecting them into a vector first

        let trusted_keys = fs::read_dir(&keys_dir)?
            .filter_map(|entry_result| entry_result.ok())
            .filter(|entry| {
                let path = entry.path();
                path.is_file()
                    && path.extension() == Some("pub".as_ref())
                    // This implicitly filters out '.' and '..'
            })
            // The directory will not be read beyond this number of valid files
            .take(config.max_trusted_ak_keys);

        for entry in trusted_keys {
            let path = entry.path();

            let key_content = fs::read_to_string(&path)?;
            let pkey = PKey::public_key_from_pem(key_content.as_bytes())
                .context("Failed to parse PEM public key")?;
            let key_bytes = pkey.public_key_to_der()
                .context("Failed to convert PEM to DER")?;
            let hash = Sha256::digest(&key_bytes).to_vec();
            trusted_ak_hashes.insert(hash);
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

    debug!("Expected report_data ({} bytes): {}", expected_report_data.len(), hex::encode(expected_report_data));
    debug!("Quote nonce ({} bytes): {}", nonce.len(), hex::encode(&nonce));

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
            if &digest == init_data_pcr {
                Ok(())
            } else {
                bail!("TPM PCR[8] doesn't match expected init_data_hash")
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
    for (i, pcr) in pcrs.iter().enumerate() {
        map.insert(
            format!("pcr{:02}", i),
            serde_json::Value::String(hex::encode(pcr)),
        );
    }
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
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        // Try to deserialize in guest-components format first, then fall back to original format
        let ev = if let std::result::Result::Ok(guest_ev) =
            serde_json::from_value::<GuestComponentsEvidence>(evidence.clone())
        {
            let quote = guest_ev
                .tpm_quote
                .to_quote()
                .context("Failed to convert quote from string format")?;
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

        if !self.trusted_ak_hashes.contains(&ak_public_hash) {
            bail!("The provided AK public key is not in the list of trusted keys");
        }

        // 2. Verify the quote signature using the (now trusted) AK pubkey
        verify_signature(&ev.quote, &ev.ak_public)?;

        // 3. Verify PCRs
        verify_pcrs(&ev.quote)?;

        // 4. Verify nonce/report data
        if let ReportData::Value(report_data) = expected_report_data {
            verify_nonce(&ev.quote, report_data)?;
        }

        // 5. Verify init data hash
        verify_init_data(expected_init_data_hash, &ev.quote)?;

        // 6. Parse claims
        let mut claims = parse_tee_evidence(&ev.quote);
        extend_claim(&mut claims, &ev.quote)?;

        Ok(vec![(claims, "cpu".to_string())])
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

}
