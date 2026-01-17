// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

mod compat;

use self::compat::Evidence;
use super::az_snp_vtpm::{
    extend_claim, verify_init_data, verify_tpm_nonce, verify_tpm_pcrs, verify_tpm_signature,
    TpmQuote,
};
use super::tdx::claims::generate_parsed_claim;
use super::tdx::quote::{parse_tdx_quote, Quote as TdQuote};
use super::{TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
use crate::intel_dcap::{ecdsa_quote_verification, extend_using_custom_claims};
use crate::{InitDataHash, ReportData};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use az_tdx_vtpm::hcl::HclReport;
use tracing::{debug, instrument};

#[derive(Default)]
pub struct AzTdxVtpm;

#[async_trait]
impl Verifier for AzTdxVtpm {
    /// The following verification steps are performed:
    /// 1. TPM Quote has been signed by AK included in the HCL variable data
    /// 2. Attestation nonce matches TPM Quote nonce
    /// 3. TPM PCRs' digest matches the digest in the Quote
    /// 4. TD Quote is genuine
    /// 5. TD Report's report_data field matches hashed HCL variable data
    /// 6. Init data hash matches TPM PCR[INITDATA_PCR]
    #[instrument(skip_all, name = "Azure vTPM TDX")]
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
            .context("Failed to deserialize Azure vTPM TDX evidence")?;

        let hcl_report = HclReport::new(evidence.hcl_report().into())?;
        let tpm_quote = evidence.tpm_quote()?;
        verify_tpm_signature(&tpm_quote, &hcl_report)?;

        verify_tpm_nonce(&tpm_quote, expected_report_data)?;

        verify_tpm_pcrs(&tpm_quote)?;

        let custom_claims = ecdsa_quote_verification(evidence.td_quote()).await?;
        let td_quote = parse_tdx_quote(evidence.td_quote())?;

        verify_hcl_var_data(&hcl_report, &td_quote)?;

        let pcrs = get_pcrs(&tpm_quote)?;
        let pcr_refs: Vec<&[u8; 32]> = pcrs.iter().collect();
        verify_init_data(expected_init_data_hash, &pcr_refs)?;

        let mut claim = generate_parsed_claim(td_quote, None)?;
        extend_claim(&mut claim, &tpm_quote)?;
        extend_using_custom_claims(&mut claim, custom_claims)?;

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

fn verify_hcl_var_data(hcl_report: &HclReport, td_quote: &TdQuote) -> Result<()> {
    let var_data_hash = hcl_report.var_data_sha256();
    if var_data_hash != td_quote.report_data()[..32] {
        bail!("TDX Quote report data mismatch");
    }
    debug!("Report data verification completed successfully.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const REPORT: &[u8; 2600] = include_bytes!("../../test_data/az-tdx-vtpm/hcl-report.bin");
    const TPM_QUOTE_V1_JSON: &str = include_str!("../../test_data/az-tdx-vtpm/tpm-quote-v1.json");
    const TD_QUOTE: &[u8; 5006] = include_bytes!("../../test_data/az-tdx-vtpm/td-quote.bin");
    const REPORT_DATA: &[u8] = "challenge".as_bytes();
    const EVIDENCE_V0_JSON: &str = include_str!("../../test_data/az-tdx-vtpm/evidence-v0.json");
    const EVIDENCE_V1_JSON: &str = include_str!("../../test_data/az-tdx-vtpm/evidence-v1.json");

    fn load_tpm_quote() -> TpmQuote {
        serde_json::from_str(TPM_QUOTE_V1_JSON).unwrap()
    }

    // Note: these tests are skipped by default because they depend on a collateral service
    #[rstest]
    #[ignore]
    #[case::v0(EVIDENCE_V0_JSON)]
    #[ignore]
    #[case::v1(EVIDENCE_V1_JSON)]
    #[tokio::test]
    async fn test_evaluate(#[case] evidence_json: &str) {
        let tee_evidence: TeeEvidence = serde_json::from_str(evidence_json).unwrap();
        let verifier = AzTdxVtpm;
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
                == "782b20b10f55cc46e2142cc2145d548698073e5beb82752c8d7f9279f0d8a273"
        );
    }

    #[test]
    fn test_verify_hcl_var_data() {
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        let td_quote = parse_tdx_quote(TD_QUOTE).unwrap();
        verify_hcl_var_data(&hcl_report, &td_quote).unwrap();
    }

    #[test]
    fn test_verify_hcl_var_data_failure() {
        let mut wrong_report = *REPORT;
        wrong_report[0x0880] += 1;
        let hcl_report = HclReport::new(wrong_report.to_vec()).unwrap();
        let td_quote = parse_tdx_quote(TD_QUOTE).unwrap();
        assert_eq!(
            verify_hcl_var_data(&hcl_report, &td_quote)
                .unwrap_err()
                .to_string(),
            "TDX Quote report data mismatch"
        );
    }

    #[test]
    fn test_verify_tpm_signature() {
        let tpm_quote = load_tpm_quote();
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        verify_tpm_signature(&tpm_quote, &hcl_report).unwrap();
    }

    #[test]
    fn test_verify_tpm_signature_failure() {
        let mut tpm_quote = load_tpm_quote();
        tpm_quote.signature[0] ^= 1;

        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        assert!(verify_tpm_signature(&tpm_quote, &hcl_report).is_err());
    }

    #[test]
    fn test_verify_tpm_nonce() {
        let tpm_quote = load_tpm_quote();
        verify_tpm_nonce(&tpm_quote, REPORT_DATA).unwrap();
    }

    #[test]
    fn test_verify_tpm_nonce_failure() {
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
}
