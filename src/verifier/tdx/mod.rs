use anyhow::{anyhow, Context, Result};
extern crate serde;
extern crate strum;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64;
use cc_measurement::log::CcEventLogReader;
use eventlog::{CcEventLog, MeasuredEntity, ParsedUefiPlatformFirmwareBlob2, Rtmr};
use quote::{ecdsa_quote_verification, parse_tdx_quote, Quote};
use serde_json::{Map, Value};
use sha2::{Digest, Sha384};

mod eventlog;
mod quote;

#[derive(Serialize, Deserialize, Debug)]
struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct Tdx {}

#[async_trait]
impl Verifier for Tdx {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tdx_evidence = serde_json::from_str::<TdxEvidence>(&attestation.tee_evidence)
            .context("Deserialize TDX Evidence failed.")?;

        let mut hasher = Sha384::new();
        hasher.update(&nonce);
        hasher.update(&attestation.tee_pubkey.k);
        let mut hash_of_nonce_pubkey = hasher.finalize().to_vec();
        hash_of_nonce_pubkey.extend([0; 16]);

        log::info!(
            "HASH(nonce||pubkey):\n\t{}\n",
            hex::encode(&hash_of_nonce_pubkey)
        );

        verify_evidence(hash_of_nonce_pubkey, &tdx_evidence)
            .await
            .map_err(|e| anyhow!("TDX Verifier: {:?}", e))
    }
}

#[allow(unused_assignments)]
async fn verify_evidence(
    hash_of_nonce_pubkey: Vec<u8>,
    evidence: &TdxEvidence,
) -> Result<TeeEvidenceParsedClaim> {
    // Verify TD quote ECDSA signature.
    let quote_bin = base64::decode(evidence.quote.clone())?;
    ecdsa_quote_verification(quote_bin.as_slice()).await?;

    // Parse quote and Compare report data
    let quote = parse_tdx_quote(&quote_bin)?;

    log::info!("{}\n", &quote);

    if hash_of_nonce_pubkey != quote.report_body.report_data.to_vec() {
        return Err(anyhow!(
            "HASH(nonce||pubkey) is different from that in TDX Quote"
        ));
    }

    // Verify Integrity of CC Eventlog
    let mut ccel_data = Vec::default();
    let mut ccel_option = Option::default();
    match &evidence.cc_eventlog {
        Some(el) => {
            ccel_data = base64::decode(el)?;
            let reader = CcEventLogReader::new(ccel_data.as_slice())
                .ok_or_else(|| anyhow!("Parse CC Eventlog failed"))?;
            let ccel = CcEventLog {
                cc_events: reader.cc_events,
            };
            ccel_option = Some(ccel.clone());

            log::debug!("Get CC Eventlog. \n{}\n", &ccel);

            let rtmr_from_quote = Rtmr {
                rtmr0: quote.report_body.rtmr_0,
                rtmr1: quote.report_body.rtmr_1,
                rtmr2: quote.report_body.rtmr_2,
                rtmr3: quote.report_body.rtmr_3,
            };

            ccel.integrity_check(rtmr_from_quote)?;
        }
        None => {
            warn!("There is no CC EventLog in Evidence!!!");
        }
    }

    // Return Evidence parsed claim
    generate_parsed_claim(quote, ccel_option)
}

fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
) -> Result<TeeEvidenceParsedClaim> {
    // Current Parsed Claim just a example
    // TODO: Claim key name shall be consistent with RVPS

    let mut claim_map = Map::new();

    // Claims from TD Quote.
    claim_map.insert(
        "tdx-tcb-svn".to_string(),
        serde_json::Value::String(hex::encode(quote.report_body.tcb_svn)),
    );
    claim_map.insert(
        "tdx-mrseam".to_string(),
        serde_json::Value::String(hex::encode(quote.report_body.mr_seam)),
    );
    claim_map.insert(
        "tdx-mrtd".to_string(),
        serde_json::Value::String(hex::encode(quote.report_body.mr_td)),
    );
    claim_map.insert(
        "tdx-mrconfigid".to_string(),
        serde_json::Value::String(hex::encode(quote.report_body.mr_config_id)),
    );

    // Claims from CC EventLog.
    match cc_eventlog {
        Some(ccel) => {
            match (
                ccel.query_digest(MeasuredEntity::TdPayload),
                ccel.query_event_data(MeasuredEntity::TdPayload),
            ) {
                (Some(td_paylod_digest), Some(event_data)) => {
                    let uefi_platform_firmware_blob2 =
                        ParsedUefiPlatformFirmwareBlob2::try_from(event_data)
                            .map_err(|e| anyhow!("Parse td_payload event data failed: {:?}", e))?;
                    let digest_name = format!(
                        "tdx-kernel-size{:?}",
                        uefi_platform_firmware_blob2.blob_length
                    );
                    claim_map.insert(digest_name, serde_json::Value::String(td_paylod_digest));
                }
                _ => {
                    warn!("parse CC EventLog: There is no tdx kernel measurement entry")
                }
            }
        }
        None => {
            warn!("parse CC EventLog: CCEL is null")
        }
    }

    log::info!("\nParsed Evidence claims map: \n{:?}\n", &claim_map);

    Ok(Value::Object(claim_map) as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cc_measurement::log::CcEventLogReader;
    use std::fs;

    #[test]
    fn test_generate_parsed_claim() {
        let ccel_bin = fs::read("test_data/CCEL_data").unwrap();
        let reader = CcEventLogReader::new(ccel_bin.as_slice()).unwrap();
        let ccel = CcEventLog {
            cc_events: reader.cc_events,
        };
        let quote_bin = fs::read("test_data/tdx_quote_4.dat").unwrap();
        let quote = parse_tdx_quote(&quote_bin).unwrap();

        let parsed_claim = generate_parsed_claim(quote, Some(ccel));
        assert!(parsed_claim.is_ok());

        let _ = fs::write(
            "test_data/evidence_claim_output.txt",
            format!("{:?}", parsed_claim.unwrap()),
        );
    }
}
