// Copyright (C) Copyright Confidential Containers Project Authors.
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use async_trait::async_trait;
use az_cvm_vtpm::vtpm::Quote as VtpmQuote;
use base64::{Engine, engine::general_purpose};
use hex;
use openssl::pkey::PKey;
use serde::Deserialize;
use serde_json::{self, json};
use std::collections::BTreeMap;
use std::result::Result::Ok;
use tracing::{debug, instrument};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Attest, AttestInfo, Signature};
use tss_esapi::traits::UnMarshall;

use super::*;

const INITDATA_PCR: usize = 8;
const TPM_REPORT_DATA_SIZE: usize = 32;

// TPM evidence format as sent by the TPM attester
#[derive(Deserialize, Debug)]
pub struct Evidence {
    pub ak_public: String,
    pub tpm_quote: Quote,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TpmVerifierConfig {}

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

    /// Extract PCR selection from the TPM quote message and return a mapping
    /// of PCR slot numbers to their corresponding values from the pcrs array.
    fn get_pcr_map(&self) -> Result<BTreeMap<usize, [u8; 32]>> {
        let message_bytes = general_purpose::STANDARD
            .decode(&self.message)
            .context("Failed to decode message from base64")?;

        let attest = Attest::unmarshall(&message_bytes).context("Failed to parse TPM message")?;
        let AttestInfo::Quote { info } = attest.attested() else {
            bail!("TPM attestation is not a quote");
        };

        let [pcr_selection] = info.pcr_selection().get_selections() else {
            bail!("TPM quote should have 1 PCR bank selection");
        };

        if pcr_selection.hashing_algorithm() != HashingAlgorithm::Sha256 {
            bail!("TPM quote has unexpected hashing algorithm");
        }

        // Map the PCR selection's bitmask to a vector of PCR indices that are selected.
        let pcr_slots: Vec<usize> = pcr_selection
            .selected()
            .iter()
            .map(|&slot| (slot as u32).trailing_zeros() as usize)
            .collect();

        let pcr_values = self.parse_pcr_values()?;
        if pcr_slots.len() != pcr_values.len() {
            bail!(
                "PCR count mismatch: selection has {} slots but {} values provided",
                pcr_slots.len(),
                pcr_values.len()
            );
        }

        let pcr_map: BTreeMap<usize, [u8; 32]> = pcr_slots.into_iter().zip(pcr_values).collect();

        Ok(pcr_map)
    }
}

#[derive(Debug, Default)]
pub struct TpmVerifier {}

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

    // TPM attester pads report_data to 32 bytes, so we need to pad expected_report_data the same way
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

fn verify_init_data(expected: &InitDataHash, pcr_map: &BTreeMap<usize, [u8; 32]>) -> Result<()> {
    match expected {
        InitDataHash::Value(expected_init_data_hash) => {
            debug!("Check the binding of PCR{INITDATA_PCR}");

            // sha256(0x00 * 32 || expected_init_data_hash)
            let mut input = [0u8; 64];
            input[32..].copy_from_slice(expected_init_data_hash);
            let digest = openssl::sha::sha256(&input);

            let init_data_pcr = pcr_map
                .get(&INITDATA_PCR)
                .ok_or_else(|| anyhow!("PCR{INITDATA_PCR} not found in quote"))?;
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

fn extend_claim(
    claim: &mut TeeEvidenceParsedClaim,
    pcr_map: &BTreeMap<usize, [u8; 32]>,
) -> Result<()> {
    let serde_json::Value::Object(map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    for (slot, pcr) in pcr_map.iter() {
        map.insert(
            format!("pcr{:02}", slot),
            serde_json::Value::String(hex::encode(pcr)),
        );
    }
    Ok(())
}

#[async_trait]
impl Verifier for TpmVerifier {
    #[instrument(skip_all, name = "TPM")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let guest_ev = serde_json::from_value::<Evidence>(evidence)
            .context("Failed to deserialize TPM Evidence")?;

        // Extract PCR mapping before converting to VtpmQuote
        let pcr_map = guest_ev
            .tpm_quote
            .get_pcr_map()
            .context("Failed to extract PCR mapping")?;

        let quote = guest_ev
            .tpm_quote
            .to_quote()
            .context("Failed to convert quote from string format")?;

        let ak_public = guest_ev.ak_public;

        // 1. Verify the quote signature using the (now trusted) AK pubkey
        verify_signature(&quote, &ak_public)?;

        // 2. Verify PCRs
        verify_pcrs(&quote)?;

        // 3. Verify nonce/report data
        if let ReportData::Value(report_data) = expected_report_data {
            verify_nonce(&quote, report_data)?;
        }

        // 4. Verify init data hash
        verify_init_data(expected_init_data_hash, &pcr_map)?;

        // 5. Parse claims
        let mut claims = parse_tee_evidence(&pcr_map, &quote, &ak_public);
        extend_claim(&mut claims, &pcr_map)?;

        Ok(vec![(claims, "cpu".to_string())])
    }
}

pub fn parse_tee_evidence(
    pcr_map: &BTreeMap<usize, [u8; 32]>,
    quote: &VtpmQuote,
    ak_public: &str,
) -> TeeEvidenceParsedClaim {
    let mut claims_map = json!({
        "report_data": hex::encode(quote.nonce().unwrap_or_default()),
        "ak_public": ak_public,
    });

    // Only include init_data if PCR 8 is present
    if let Some(init_data_pcr) = pcr_map.get(&INITDATA_PCR) {
        claims_map
            .as_object_mut()
            .unwrap()
            .insert("init_data".to_string(), json!(hex::encode(init_data_pcr)));
    }

    claims_map as TeeEvidenceParsedClaim
}

#[cfg(test)]
mod tests {
    use super::*;

    const TPM_EVIDENCE: &[u8] = include_bytes!("../../test_data/tpm_evidence.json");
    const SPARSE_TPM_EVIDENCE: &[u8] = include_bytes!("../../test_data/sparse_tpm_evidence.json");

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
        let pcr_map = tpm_evidence
            .tpm_quote
            .get_pcr_map()
            .expect("Failed to get PCR map");
        let quote = tpm_evidence
            .tpm_quote
            .to_quote()
            .context("Failed to convert quote from string format")
            .unwrap();

        let claims = parse_tee_evidence(&pcr_map, &quote, &tpm_evidence.ak_public);

        // Verify claims contain expected fields
        assert!(
            claims.get("init_data").is_some(),
            "Claims should contain init_data"
        );
        assert!(
            claims.get("report_data").is_some(),
            "Claims should contain report_data"
        );
        assert!(
            claims.get("ak_public").is_some(),
            "Claims should contain ak_public"
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

    #[test]
    fn test_sparse_pcr_mapping() {
        // Test that sparse PCR quotes are correctly mapped to slot numbers
        // This sparse quote has 9 PCRs: slots 0,1,2,3,4,5,6,7,11
        // Note: The fixture uses a message from az-snp-vtpm test data
        let sparse_evidence = serde_json::from_slice::<Evidence>(SPARSE_TPM_EVIDENCE)
            .expect("Failed to deserialize sparse TPM Evidence");

        let pcr_map = sparse_evidence
            .tpm_quote
            .get_pcr_map()
            .expect("Failed to get PCR map");

        // Verify we have exactly 9 PCRs
        assert_eq!(pcr_map.len(), 9, "Should have 9 PCRs in sparse quote");

        // Verify the correct slots are present
        for slot in 0..=7 {
            assert!(
                pcr_map.contains_key(&slot),
                "PCR slot {} should be present",
                slot
            );
        }
        assert!(pcr_map.contains_key(&11), "PCR slot 11 should be present");

        // Verify slot 8 is NOT present (this would be the bug case)
        assert!(
            !pcr_map.contains_key(&8),
            "PCR slot 8 should NOT be present"
        );

        // Verify the last value corresponds to PCR 11, not PCR 8
        let pcr11_value = pcr_map.get(&11).unwrap();
        let expected_pcr11 =
            hex::decode("2aa12c5cfb13e017d1c95f389d4803f51a4b3097f583e9da0c803b3bcef7e29d")
                .unwrap();
        assert_eq!(
            &pcr11_value[..],
            &expected_pcr11[..],
            "PCR 11 value should match last entry in sparse evidence"
        );

        // Test that claims are correctly populated
        // We create a mock VtpmQuote for claim generation since the fixture
        // signature format is incompatible (it's from az-vtpm, not TPM verifier format)
        let message_bytes = general_purpose::STANDARD
            .decode(&sparse_evidence.tpm_quote.message)
            .expect("Failed to decode message");
        let quote_data = serde_json::json!({
            "signature": vec![0u8; 256],  // Mock signature
            "message": message_bytes,
            "pcrs": sparse_evidence.tpm_quote.pcrs.iter()
                .map(|s| hex::decode(s).unwrap())
                .collect::<Vec<Vec<u8>>>()
        });
        let mock_quote =
            serde_json::from_value::<VtpmQuote>(quote_data).expect("Failed to create mock quote");

        let mut claims = parse_tee_evidence(&pcr_map, &mock_quote, &sparse_evidence.ak_public);
        extend_claim(&mut claims, &pcr_map).expect("Failed to extend claim");

        let claims_obj = claims.as_object().unwrap();

        // Verify PCR claims are correctly mapped
        assert!(claims_obj.contains_key("pcr00"), "Should have pcr00");
        assert!(claims_obj.contains_key("pcr07"), "Should have pcr07");
        assert!(claims_obj.contains_key("pcr11"), "Should have pcr11");
        assert!(!claims_obj.contains_key("pcr08"), "Should NOT have pcr08");
        assert!(!claims_obj.contains_key("pcr09"), "Should NOT have pcr09");
        assert!(!claims_obj.contains_key("pcr10"), "Should NOT have pcr10");

        // Verify init_data is not present (PCR 8 is missing)
        assert!(
            !claims_obj.contains_key("init_data"),
            "init_data should not be present when PCR 8 is missing"
        );

        // Verify pcr11 claim matches the expected value
        let pcr11_claim = claims_obj.get("pcr11").unwrap().as_str().unwrap();
        assert_eq!(
            pcr11_claim,
            "2aa12c5cfb13e017d1c95f389d4803f51a4b3097f583e9da0c803b3bcef7e29d"
        );
    }
}
