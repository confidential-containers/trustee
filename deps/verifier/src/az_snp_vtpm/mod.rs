// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

mod compat;

use self::compat::Evidence;
use super::{TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
use crate::snp::{
    get_common_name, get_oid_int, get_oid_octets, ProcessorGeneration, CERT_CHAINS, HW_ID_OID,
    LOADER_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, UCODE_SPL_OID,
};
use crate::{InitDataHash, ReportData};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use az_snp_vtpm::certs::{AmdChain, Vcek};
use az_snp_vtpm::hcl::HclReport;
use az_snp_vtpm::report::AttestationReport;
use az_snp_vtpm::vtpm::QuoteError;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
pub(crate) use compat::TpmQuote;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Verifier as OsslVerifier;
use openssl::x509::X509;
use openssl::{ec::EcKey, ecdsa, sha::sha384};
use serde_json::{json, Value};
use sev::parser::ByteParser;
use thiserror::Error;
use tracing::{debug, instrument};
use tss_esapi::structures::{Attest, AttestInfo};
use tss_esapi::traits::UnMarshall;
use x509_parser::prelude::*;

const HCL_VMPL_VALUE: u32 = 0;
const INITDATA_PCR: usize = 8;
const SNP_REPORT_SIGNATURE_OFFSET: usize = 0x2a0; // 672 bytes

struct AzVendorCertificates {
    ca_chain: AmdChain,
}

pub struct AzSnpVtpm {
    vendor_certs: AzVendorCertificates,
}

#[derive(Error, Debug)]
pub enum CertError {
    #[error("Failed to load Milan cert chain")]
    LoadMilanCert,
    #[error("TPM quote nonce doesn't match expected report_data")]
    NonceMismatch,
    #[error("SNP report report_data mismatch")]
    SnpReportMismatch,
    #[error("VMPL of SNP report is not {0}")]
    VmplIncorrect(u32),
    #[error(transparent)]
    Quote(#[from] QuoteError),
    #[error(transparent)]
    JsonWebkey(#[from] jsonwebkey::ConversionError),
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

// Azure vTPM still initialized to Milan only certs until az_snp_vtpm crate gets updated.
impl AzSnpVtpm {
    pub fn new() -> Result<Self, CertError> {
        let vendor_certs = CERT_CHAINS
            .get(&ProcessorGeneration::Milan)
            .ok_or(CertError::LoadMilanCert)?
            .clone();
        Ok(Self {
            vendor_certs: AzVendorCertificates {
                ca_chain: AmdChain {
                    ask: vendor_certs.ask.into(),
                    ark: vendor_certs.ark.into(),
                },
            },
        })
    }
}

pub(crate) fn extend_claim(claim: &mut TeeEvidenceParsedClaim, tpm_quote: &TpmQuote) -> Result<()> {
    let Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    let mut tpm_values = serde_json::Map::new();
    for (i, pcr) in tpm_quote.pcrs.iter().enumerate() {
        tpm_values.insert(format!("pcr{:02}", i), Value::String(hex::encode(pcr)));
    }
    map.insert("tpm".to_string(), Value::Object(tpm_values));
    if tpm_quote.pcrs.len() > INITDATA_PCR {
        map.insert(
            "init_data".into(),
            Value::String(hex::encode(&tpm_quote.pcrs[INITDATA_PCR])),
        );
    }
    let nonce = extract_nonce(&tpm_quote.message)?;
    map.insert("report_data".into(), Value::String(hex::encode(nonce)));
    Ok(())
}

fn extract_nonce(message: &[u8]) -> Result<Vec<u8>> {
    let attest = Attest::unmarshall(message).context("Failed to parse TPM quote message")?;
    Ok(attest.extra_data().to_vec())
}

#[async_trait]
impl Verifier for AzSnpVtpm {
    /// The following verification steps are performed:
    /// 1. TPM Quote has been signed by AK included in the HCL variable data
    /// 2. Attestation report_data matches TPM Quote nonce
    /// 3. TPM PCRs' digest matches the digest in the Quote
    /// 4. SNP report's report_data field matches hashed HCL variable data
    /// 5. SNP Report is genuine
    /// 6. SNP Report has been issued in VMPL 0
    /// 7. Init data hash matches TPM PCR[INITDATA_PCR]
    #[instrument(skip_all, name = "Azure vTPM SEV-SNP")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let ReportData::Value(expected_report_data) = expected_report_data else {
            bail!("unexpected empty report data");
        };

        let evidence = serde_json::from_value::<Evidence>(evidence)
            .context("Failed to deserialize Azure vTPM SEV-SNP evidence")?;

        let hcl_report = HclReport::new(evidence.hcl_report().into())?;
        let tpm_quote = &evidence.tpm_quote()?;
        verify_tpm_signature(tpm_quote, &hcl_report)?;

        verify_tpm_nonce(tpm_quote, expected_report_data)?;

        verify_tpm_pcrs(tpm_quote)?;

        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report = hcl_report.try_into()?;
        verify_report_data(&var_data_hash, &snp_report)?;

        let vcek_x509: X509 = match evidence.vcek()? {
            compat::Vcek::Pem(pem) => pem,
            compat::Vcek::Der(der) => X509::from_der(&der).context("Invalid VCEK DER")?,
        };
        let vcek = Vcek(vcek_x509);

        self.vendor_certs
            .ca_chain
            .validate()
            .context("Failed to validate CA chain")?;
        vcek.validate(&self.vendor_certs.ca_chain)
            .context("Failed to validate VCEK")?;

        verify_snp_report(&snp_report, &vcek)?;

        let pcrs = get_pcrs(tpm_quote)?;
        let pcr_refs: Vec<&[u8; 32]> = pcrs.iter().collect();
        verify_init_data(expected_init_data_hash, &pcr_refs)?;

        let mut claim = parse_tee_evidence_az(&snp_report);
        extend_claim(&mut claim, tpm_quote)?;

        Ok(vec![(claim, "cpu".to_string())])
    }
}

fn get_pcrs(tpm_quote: &TpmQuote) -> Result<Vec<[u8; 32]>> {
    tpm_quote
        .pcrs
        .iter()
        .map(|p| {
            p.as_slice()
                .try_into()
                .context("Invalid PCR length, expected 32 bytes")
        })
        .collect()
}

pub(crate) fn verify_tpm_nonce(tpm_quote: &TpmQuote, report_data: &[u8]) -> Result<()> {
    let nonce = extract_nonce(&tpm_quote.message)?;
    if nonce != report_data[..] {
        bail!("TPM quote nonce doesn't match expected report_data");
    }
    debug!("TPM report_data verification completed successfully");
    Ok(())
}

pub(crate) fn verify_tpm_signature(tpm_quote: &TpmQuote, hcl_report: &HclReport) -> Result<()> {
    let ak_pub = hcl_report.ak_pub().context("Failed to get AKpub")?;
    let der = ak_pub.key.try_to_der()?;
    let ak_pub = PKey::public_key_from_der(&der).context("Failed to parse AKpub")?;

    let mut verifier = OsslVerifier::new(MessageDigest::sha256(), &ak_pub)?;
    verifier.update(&tpm_quote.message)?;
    let is_verified = verifier.verify(&tpm_quote.signature)?;
    if !is_verified {
        bail!("vTPM quote is not signed by AKpub");
    }
    debug!("Signature verification completed successfully");
    Ok(())
}

pub(crate) fn verify_tpm_pcrs(tpm_quote: &TpmQuote) -> Result<()> {
    let attest = Attest::unmarshall(&tpm_quote.message).context("Failed to parse TPM message")?;
    let AttestInfo::Quote { info } = attest.attested() else {
        bail!("TPM attestation is not a quote");
    };
    let expected_digest = info.pcr_digest();

    let mut hasher = openssl::sha::Sha256::new();
    for pcr in &tpm_quote.pcrs {
        hasher.update(pcr);
    }
    let actual_digest = hasher.finish();

    if actual_digest[..] != expected_digest[..] {
        bail!("Digest of PCRs does not match digest in Quote");
    }
    debug!("PCR verification completed successfully");
    Ok(())
}

fn verify_report_data(
    var_data_hash: &[u8; 32],
    snp_report: &AttestationReport,
) -> Result<(), CertError> {
    if *var_data_hash != snp_report.report_data[..32] {
        return Err(CertError::SnpReportMismatch);
    }
    debug!("SNP report_data verification completed successfully");
    Ok(())
}

fn verify_snp_report(snp_report: &AttestationReport, vcek: &Vcek) -> Result<(), CertError> {
    verify_report_signature(snp_report, vcek)?;

    if snp_report.vmpl != HCL_VMPL_VALUE {
        return Err(CertError::VmplIncorrect(HCL_VMPL_VALUE));
    }

    Ok(())
}

/// Verifies the signature of the attestation report using the provided certificate chain and vendor certificates.
fn verify_report_signature(report: &AttestationReport, vcek: &Vcek) -> Result<()> {
    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser

    let endorsement_key_der = &vcek.0.to_der()?;
    let parsed_endorsement_key = X509Certificate::from_der(endorsement_key_der)?
        .1
        .tbs_certificate;

    let common_name = get_common_name(&vcek.0).context("No common name found in certificate")?;

    // if the common name is "VCEK", then the key is a VCEK
    // so lets check the chip id
    if common_name == "VCEK"
        && get_oid_octets::<64>(&parsed_endorsement_key, HW_ID_OID)? != report.chip_id
    {
        bail!("Chip ID mismatch");
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_endorsement_key, UCODE_SPL_OID)? != report.reported_tcb.microcode {
        bail!("Microcode version mismatch");
    }

    if get_oid_int(&parsed_endorsement_key, SNP_SPL_OID)? != report.reported_tcb.snp {
        bail!("SNP version mismatch");
    }

    if get_oid_int(&parsed_endorsement_key, TEE_SPL_OID)? != report.reported_tcb.tee {
        bail!("TEE version mismatch");
    }

    if get_oid_int(&parsed_endorsement_key, LOADER_SPL_OID)? != report.reported_tcb.bootloader {
        bail!("Boot loader version mismatch");
    }

    // verify report signature
    let sig = ecdsa::EcdsaSig::try_from(&report.signature)?;
    // Get the offset of the signature field in the report struct
    let raw_report_bytes = report.to_bytes().context("Failed to write report bytes")?;
    let data = &raw_report_bytes[..SNP_REPORT_SIGNATURE_OFFSET];

    let pub_key = EcKey::try_from(vcek.0.public_key()?)?;
    let signed = sig.verify(&sha384(data), &pub_key)?;
    if !signed {
        bail!("Signature validation failed.");
    }

    Ok(())
}

pub(crate) fn verify_init_data(expected: &InitDataHash, pcrs: &[&[u8; 32]]) -> Result<()> {
    let InitDataHash::Value(expected_init_data_hash) = expected else {
        debug!("No expected value, skipping init_data verification");
        return Ok(());
    };

    debug!("Check the binding of PCR{INITDATA_PCR}");

    // sha256(0x00 * 32 || expected_init_data_hash)
    let mut input = [0u8; 64];
    input[32..].copy_from_slice(expected_init_data_hash);
    let digest = openssl::sha::sha256(&input);

    let init_data_pcr = pcrs[INITDATA_PCR];
    if &digest != init_data_pcr {
        bail!("Expected init_data digest is different from the content of PCR{INITDATA_PCR}");
    }
    Ok(())
}

/// Parses the attestation report and extracts the TEE evidence claims.
/// Returns a JSON-formatted map of parsed claims.
pub(crate) fn parse_tee_evidence_az(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", report.reported_tcb.bootloader),
        "reported_tcb_tee": format!("{}", report.reported_tcb.tee),
        "reported_tcb_snp": format!("{}", report.reported_tcb.snp),
        "reported_tcb_microcode": format!("{}", report.reported_tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurements
        "measurement": format!("{}", STANDARD.encode(report.measurement)),
        "report_data": format!("{}", STANDARD.encode(report.report_data)),
        "init_data": format!("{}", STANDARD.encode(report.host_data)),
    });

    claims_map as TeeEvidenceParsedClaim
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use serde_json::json;

    const REPORT: &[u8; 2600] = include_bytes!("../../test_data/az-snp-vtpm/hcl-report.bin");
    const TPM_QUOTE_V1_JSON: &str = include_str!("../../test_data/az-snp-vtpm/tpm-quote-v1.json");
    const REPORT_DATA: &[u8] = "challenge".as_bytes();
    const EVIDENCE_V0_JSON: &str = include_str!("../../test_data/az-snp-vtpm/evidence-v0.json");
    const EVIDENCE_V1_JSON: &str = include_str!("../../test_data/az-snp-vtpm/evidence-v1.json");

    fn load_tpm_quote() -> TpmQuote {
        serde_json::from_str(TPM_QUOTE_V1_JSON).unwrap()
    }

    #[rstest]
    #[case::v0(EVIDENCE_V0_JSON)]
    #[case::v1(EVIDENCE_V1_JSON)]
    #[tokio::test]
    async fn test_evaluate(#[case] evidence_json: &str) {
        let tee_evidence: TeeEvidence = serde_json::from_str(evidence_json).unwrap();
        let verifier = AzSnpVtpm::new().unwrap();
        let result = verifier
            .evaluate(
                tee_evidence,
                &ReportData::Value(REPORT_DATA),
                &InitDataHash::NotProvided,
            )
            .await;
        let claims = result.unwrap();
        let claims_values = claims[0].0.clone();
        assert!(claims_values["report_data"] == "6368616c6c656e6765");
        assert!(
            claims_values["tpm"]["pcr00"]
                == "f3a7e99a5f819a034386bce753a48a73cfdaa0bea0ecfc124bedbf5a8c4799be"
        );
    }

    #[test]
    fn test_verify_snp_report() {
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        let snp_report = hcl_report.try_into().unwrap();
        let vcek = Vcek::from_pem(include_str!("../../test_data/az-snp-vtpm/vcek.pem")).unwrap();
        let vendor_certs = CERT_CHAINS
            .get(&ProcessorGeneration::Milan)
            .unwrap()
            .clone();
        let amd_chain = AmdChain {
            ask: vendor_certs.ask.into(),
            ark: vendor_certs.ark.into(),
        };
        amd_chain.validate().unwrap();
        vcek.validate(&amd_chain).unwrap();
        verify_snp_report(&snp_report, &vcek).unwrap();
    }

    #[test]
    fn test_verify_snp_report_failure() {
        let mut wrong_report = *REPORT;
        // messing with snp report
        wrong_report[0x01a6] = 0;
        let hcl_report = HclReport::new(wrong_report.to_vec()).unwrap();
        let snp_report = hcl_report.try_into().unwrap();
        let vcek = Vcek::from_pem(include_str!("../../test_data/az-snp-vtpm/vcek.pem")).unwrap();
        assert_eq!(
            verify_snp_report(&snp_report, &vcek)
                .unwrap_err()
                .to_string(),
            "SNP version mismatch",
        );
    }

    #[test]
    fn test_verify_report_data() {
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report = hcl_report.try_into().unwrap();
        verify_report_data(&var_data_hash, &snp_report).unwrap();
    }

    #[test]
    fn test_verify_report_data_failure() {
        let mut wrong_report = *REPORT;
        wrong_report[0x06e0] += 1;
        let hcl_report = HclReport::new(wrong_report.to_vec()).unwrap();
        let var_data_hash = hcl_report.var_data_sha256();
        let snp_report = hcl_report.try_into().unwrap();
        assert_eq!(
            verify_report_data(&var_data_hash, &snp_report)
                .unwrap_err()
                .to_string(),
            "SNP report report_data mismatch"
        );
    }

    #[test]
    fn test_verify_signature() {
        let tpm_quote = load_tpm_quote();
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        verify_tpm_signature(&tpm_quote, &hcl_report).unwrap();
    }

    #[test]
    fn test_verify_quote_signature_failure() {
        let mut tpm_quote = load_tpm_quote();
        tpm_quote.signature[0] ^= 1;

        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        assert!(verify_tpm_signature(&tpm_quote, &hcl_report).is_err());
    }

    #[test]
    fn test_verify_akpub_failure() {
        let tpm_quote = load_tpm_quote();
        let mut wrong_report = *REPORT;
        // messing with AKpub in var data
        wrong_report[0x0540] = 0;
        let wrong_hcl_report = HclReport::new(wrong_report.to_vec()).unwrap();
        assert_eq!(
            verify_tpm_signature(&tpm_quote, &wrong_hcl_report)
                .unwrap_err()
                .to_string(),
            "Failed to get AKpub",
        );
    }

    #[test]
    fn test_verify_quote_nonce() {
        let tpm_quote = load_tpm_quote();
        verify_tpm_nonce(&tpm_quote, REPORT_DATA).unwrap();
    }

    #[test]
    fn test_verify_quote_nonce_failure() {
        let tpm_quote = load_tpm_quote();
        let mut wrong_report_data = REPORT_DATA.to_vec();
        wrong_report_data.reverse();
        verify_tpm_nonce(&tpm_quote, &wrong_report_data).unwrap_err();
    }

    #[test]
    fn test_verify_pcrs() {
        let tpm_quote = load_tpm_quote();
        verify_tpm_pcrs(&tpm_quote).unwrap();
    }

    #[test]
    fn test_verify_pcrs_failure() {
        let mut tpm_quote = load_tpm_quote();
        tpm_quote.pcrs[0][0] ^= 1;

        assert!(verify_tpm_pcrs(&tpm_quote).is_err());
    }

    #[test]
    fn test_verify_init_data() {
        let tpm_quote = load_tpm_quote();
        let pcrs = get_pcrs(&tpm_quote).unwrap();

        let mut init_data_hash = [0u8; 32];
        hex::decode_to_slice(
            "8505e4e25e50a27c5dc8147af88efbece627fbea55291911eff832d9ee127781",
            &mut init_data_hash,
        )
        .unwrap();

        // sha256(0x00 * 32 || "8505...") == "bdda..."
        let mut digest = [0u8; 32];
        hex::decode_to_slice(
            "bddaccb9c52249e97a31baea61b7d91be8221a16e703d92148d04fb8e9c1dfdd",
            &mut digest,
        )
        .unwrap();

        let mut pcr_refs: Vec<&[u8; 32]> = pcrs.iter().collect();
        pcr_refs[INITDATA_PCR] = &digest;

        verify_init_data(&InitDataHash::Value(&init_data_hash), &pcr_refs).unwrap();
    }

    #[test]
    fn test_verify_init_data_failure() {
        let tpm_quote = load_tpm_quote();
        let pcrs = get_pcrs(&tpm_quote).unwrap();
        let pcr_refs: Vec<&[u8; 32]> = pcrs.iter().collect();
        let mut init_data = *pcr_refs[INITDATA_PCR];
        init_data[0] ^= 1;
        let init_data_hash = InitDataHash::Value(&init_data);

        verify_init_data(&init_data_hash, &pcr_refs).unwrap_err();
    }

    #[test]
    fn test_extend_claim() {
        let mut claim = json!({"some": "thing"});
        let tpm_quote = load_tpm_quote();
        extend_claim(&mut claim, &tpm_quote).unwrap();

        let map = claim.as_object().unwrap();
        assert_eq!(map.len(), 4);
        let tpm_map = map.get("tpm").unwrap().as_object().unwrap();
        assert_eq!(tpm_map.len(), 24);

        for (i, pcr) in tpm_quote.pcrs.iter().enumerate() {
            let key = format!("pcr{:02}", i);
            let value = tpm_map.get(&key).unwrap().as_str().unwrap();
            assert_eq!(value, hex::encode(pcr));
        }
        let init_data = map.get("init_data").unwrap().as_str().unwrap();
        assert_eq!(init_data, hex::encode(&tpm_quote.pcrs[INITDATA_PCR]));
        let report_data = map.get("report_data").unwrap().as_str().unwrap();
        assert_eq!(report_data, hex::encode(REPORT_DATA));
    }
}
