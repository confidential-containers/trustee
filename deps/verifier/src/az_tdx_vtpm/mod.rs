// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::az_snp_vtpm::{extend_claim, verify_init_data};
use super::tdx::claims::generate_parsed_claim;
use super::tdx::quote::{parse_tdx_quote, Quote as TdQuote};
use super::{TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
use crate::intel_dcap::{ecdsa_quote_verification, extend_using_custom_claims};
use crate::{InitDataHash, ReportData};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use az_tdx_vtpm::hcl::HclReport;
use az_tdx_vtpm::vtpm::Quote as TpmQuote;
use log::debug;
use openssl::pkey::PKey;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Evidence {
    tpm_quote: TpmQuote,
    hcl_report: Vec<u8>,
    td_quote: Vec<u8>,
}

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

        let hcl_report = HclReport::new(evidence.hcl_report)?;
        verify_tpm_signature(&evidence.tpm_quote, &hcl_report)?;

        verify_tpm_nonce(&evidence.tpm_quote, expected_report_data)?;

        verify_pcrs(&evidence.tpm_quote)?;

        let custom_claims = ecdsa_quote_verification(&evidence.td_quote).await?;
        let td_quote = parse_tdx_quote(&evidence.td_quote)?;

        verify_hcl_var_data(&hcl_report, &td_quote)?;

        let pcrs: Vec<&[u8; 32]> = evidence.tpm_quote.pcrs_sha256().collect();
        verify_init_data(expected_init_data_hash, &pcrs)?;

        let mut claim = generate_parsed_claim(td_quote, None)?;
        extend_claim(&mut claim, &evidence.tpm_quote)?;
        extend_using_custom_claims(&mut claim, custom_claims)?;

        Ok(vec![(claim, "cpu".to_string())])
    }
}

fn verify_hcl_var_data(hcl_report: &HclReport, td_quote: &TdQuote) -> Result<()> {
    let var_data_hash = hcl_report.var_data_sha256();
    if var_data_hash != td_quote.report_data()[..32] {
        bail!("TDX Quote report data mismatch");
    }
    debug!("Report data verification completed successfully.");
    Ok(())
}

fn verify_tpm_signature(quote: &TpmQuote, hcl_report: &HclReport) -> Result<()> {
    let ak_pub = hcl_report.ak_pub().context("Failed to get AKpub")?;
    let der = ak_pub.key.try_to_der()?;
    let ak_pub = PKey::public_key_from_der(&der).context("Failed to parse AKpub")?;

    quote
        .verify_signature(&ak_pub)
        .context("Failed to verify vTPM quote")?;
    Ok(())
}

fn verify_pcrs(quote: &TpmQuote) -> Result<()> {
    quote
        .verify_pcrs()
        .context("Digest of PCRs does not match digest in Quote")?;
    debug!("PCR verification completed successfully");
    Ok(())
}

fn verify_tpm_nonce(quote: &TpmQuote, report_data: &[u8]) -> Result<()> {
    let nonce = quote.nonce()?;
    if nonce != report_data[..] {
        bail!("TPM quote nonce doesn't match expected report_data");
    }
    debug!("TPM report_data verification completed successfully");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use az_tdx_vtpm::vtpm::Quote;
    use az_tdx_vtpm::vtpm::VerifyError;

    const REPORT: &[u8; 2600] = include_bytes!("../../test_data/az-tdx-vtpm/hcl-report.bin");
    const QUOTE: &[u8; 1170] = include_bytes!("../../test_data/az-tdx-vtpm/quote.bin");
    const TD_QUOTE: &[u8; 5006] = include_bytes!("../../test_data/az-tdx-vtpm/td-quote.bin");

    #[test]
    fn test_verify_hcl_var_data() {
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        let td_quote = parse_tdx_quote(TD_QUOTE).unwrap();
        verify_hcl_var_data(&hcl_report, &td_quote).unwrap();
    }

    #[test]
    fn test_verify_hcl_var_data_failure() {
        let mut wrong_report = REPORT.clone();
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
        let quote: Quote = bincode::deserialize(QUOTE).unwrap();
        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        verify_tpm_signature(&quote, &hcl_report).unwrap();
    }

    #[test]
    fn test_verify_tpm_signature_failure() {
        let mut quote = QUOTE.clone();
        quote[0x020] = 0;
        let wrong_quote: Quote = bincode::deserialize(&quote).unwrap();

        let hcl_report = HclReport::new(REPORT.to_vec()).unwrap();
        assert_eq!(
            verify_tpm_signature(&wrong_quote, &hcl_report)
                .unwrap_err()
                .downcast_ref::<VerifyError>()
                .unwrap()
                .to_string(),
            VerifyError::SignatureMismatch.to_string()
        );
    }

    #[test]
    fn test_verify_tpm_nonce() {
        let quote: Quote = bincode::deserialize(QUOTE).unwrap();
        let nonce = "challenge".as_bytes();
        verify_tpm_nonce(&quote, nonce).unwrap();
    }

    #[test]
    fn test_verify_tpm_nonce_failure() {
        let quote: Quote = bincode::deserialize(QUOTE).unwrap();
        let wrong_nonce = "wrong".as_bytes();
        verify_tpm_nonce(&quote, wrong_nonce).unwrap_err();
    }

    #[test]
    fn test_verify_pcrs() {
        let quote: Quote = bincode::deserialize(QUOTE).unwrap();
        verify_pcrs(&quote).unwrap();
    }

    #[test]
    fn test_verify_pcrs_failure() {
        let mut quote = QUOTE.clone();
        quote[0x0169] = 0;
        let wrong_quote: Quote = bincode::deserialize(&quote).unwrap();

        assert_eq!(
            verify_pcrs(&wrong_quote)
                .unwrap_err()
                .downcast_ref::<VerifyError>()
                .unwrap()
                .to_string(),
            VerifyError::PcrMismatch.to_string()
        );
    }
}
