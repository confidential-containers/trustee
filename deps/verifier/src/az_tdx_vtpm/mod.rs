// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

mod compat;

use self::compat::Evidence;
use super::az_snp_vtpm::{
    TpmQuote, extend_claim, verify_eventlog, verify_init_data, verify_tpm_nonce, verify_tpm_pcrs,
    verify_tpm_signature, verify_user_data,
};
use super::intel_dcap::quote::{Quote as TdQuote, parse_quote};
use super::intel_dcap::{
    QcnlConfig, collateral::build_quote_collateral, ecdsa_quote_verification,
    extend_using_custom_claims, pck::parse_platform_info,
};
use super::tdx::claims::generate_parsed_claim;
use super::{DeviceName, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
use crate::{InitDataHash, ReportData};
use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use az_tdx_vtpm::hcl::HclReport;
use tracing::{debug, instrument};

#[derive(Default)]
pub struct AzTdxVtpm {
    config: QcnlConfig,
}

impl AzTdxVtpm {
    pub(crate) fn new(config: Option<QcnlConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
        }
    }
}

#[async_trait]
impl Verifier for AzTdxVtpm {
    /// The following verification steps are performed:
    /// 1. TPM Quote has been signed by AK included in the HCL variable data
    /// 2. Attestation nonce matches TPM Quote nonce
    /// 3. TPM PCRs' digest matches the digest in the Quote
    /// 4. TD Quote is genuine
    /// 5. TD Report's report_data field matches hashed HCL variable data
    /// 6. User-data field in HCL variable data matches report_data
    /// 7. Init data hash matches TPM PCR[INITDATA_PCR]
    /// 8. AAEL runtime eventlog (if present) replays against the TPM PCRs
    #[instrument(skip_all, name = "Azure vTPM TDX")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, DeviceName)>> {
        let ReportData::Value(expected_report_data) = expected_report_data else {
            bail!("unexpected empty report data");
        };

        let evidence = serde_json::from_value::<Evidence>(evidence)
            .context("Failed to deserialize Azure vTPM TDX evidence")?;

        let hcl_report = HclReport::new(evidence.hcl_report().into())?;
        let tpm_quote = evidence.tpm_quote();
        verify_tpm_signature(&tpm_quote, &hcl_report)?;

        verify_tpm_nonce(&tpm_quote, expected_report_data)?;

        verify_tpm_pcrs(&tpm_quote)?;

        let td_quote = parse_quote(evidence.td_quote())?;
        if matches!(td_quote, TdQuote::V3 { .. }) {
            bail!("expected TDX quote (v4/v5), got SGX quote (v3)");
        }

        let platform_info =
            parse_platform_info(td_quote.cert_data().qe_certification_data.certificates)?;

        let pcs = self.config.pcs()?;
        let collateral = build_quote_collateral(
            platform_info.fmspc,
            platform_info.is_platform_ca,
            td_quote.tee_type(),
            &pcs,
        )
        .await?;

        let custom_claims = ecdsa_quote_verification(evidence.td_quote(), Some(collateral))?;

        verify_hcl_var_data(&hcl_report, &td_quote)?;

        if evidence.version() >= 2 {
            verify_user_data(&hcl_report, expected_report_data)?;
        }

        let pcrs = get_pcrs(&tpm_quote)?;
        let pcr_refs: Vec<&[u8; 32]> = pcrs.iter().collect();
        verify_init_data(expected_init_data_hash, &pcr_refs)?;

        let mut claim = generate_parsed_claim(&td_quote, None, &platform_info)?;
        extend_claim(&mut claim, &tpm_quote)?;
        extend_using_custom_claims(&mut claim, custom_claims)?;

        let ccel = verify_eventlog(evidence.cc_eventlog(), &tpm_quote)?;
        crate::extend_eventlog_claim(&mut claim, ccel)?;

        Ok(vec![(claim, "az-tdx-vtpm".to_string())])
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
        let verifier = AzTdxVtpm::default();
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
        let td_quote = parse_quote(TD_QUOTE).unwrap();
        verify_hcl_var_data(&hcl_report, &td_quote).unwrap();
    }

    #[test]
    fn test_verify_hcl_var_data_failure() {
        let mut wrong_report = *REPORT;
        wrong_report[0x0880] += 1;
        let hcl_report = HclReport::new(wrong_report.to_vec()).unwrap();
        let td_quote = parse_quote(TD_QUOTE).unwrap();
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

    /// Build a v2 evidence envelope from the v1 fixture by bumping the
    /// version tag, so we can exercise the cc_eventlog accessor without a
    /// dedicated v2 fixture file.
    fn v2_evidence_json(cc_eventlog: Option<&str>) -> String {
        let v1: serde_json::Value = serde_json::from_str(EVIDENCE_V1_JSON).unwrap();
        let mut v2 = v1.clone();
        v2["version"] = serde_json::json!(2);
        if let Some(el) = cc_eventlog {
            v2["cc_eventlog"] = serde_json::json!(el);
        } else {
            // Mimic an older v2 producer that never recorded AAEL: drop the
            // field entirely, so deserialization must tolerate its absence.
            v2.as_object_mut().unwrap().remove("cc_eventlog");
        }
        serde_json::to_string(&v2).unwrap()
    }

    #[rstest]
    #[case::with_eventlog(Some("YWFlbC1wbGFjZWhvbGRlcg=="))]
    #[case::without_eventlog(None)]
    fn test_evidence_v2_cc_eventlog(#[case] cc_eventlog: Option<&str>) {
        // Older v2 producers (pre-AAEL) emit no cc_eventlog key; the field
        // must deserialize as None rather than failing.
        let tee_evidence: TeeEvidence =
            serde_json::from_str(&v2_evidence_json(cc_eventlog)).unwrap();
        let evidence = serde_json::from_value::<Evidence>(tee_evidence).unwrap();
        assert_eq!(evidence.version(), 2);
        assert_eq!(evidence.cc_eventlog(), cc_eventlog);
    }
}
