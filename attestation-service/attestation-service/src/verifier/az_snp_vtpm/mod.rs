// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::snp::{parse_tee_evidence, verify_report_signature};
use super::{Attestation, TeeEvidenceParsedClaim, Verifier};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use az_snp_vtpm::certs::Vcek;
use az_snp_vtpm::hcl::HclData;
use az_snp_vtpm::vtpm::{Quote, VerifyVTpmQuote};
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};
use sha2::{Digest, Sha384};

const HCL_VMPL_VALUE: u32 = 0;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: Quote,
    report: Vec<u8>,
    vcek: String,
}

#[derive(Default)]
pub struct AzSnpVtpm;

#[async_trait]
impl Verifier for AzSnpVtpm {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let evidence = serde_json::from_str::<Evidence>(&attestation.tee_evidence)
            .context("Failed to deserialize vTPM SEV-SNP evidence")?;

        let hcl_data: HclData = evidence.report[..].try_into()?;
        let snp_report = hcl_data.report().snp_report();
        let vcek = Vcek::from_pem(&evidence.vcek)?;

        let hashed_quote = nonced_pub_key_hash(attestation, &nonce);
        verify_quote(&evidence.quote, &hcl_data, &hashed_quote)?;

        verify_snp_report(snp_report, &vcek)?;
        let var_data = hcl_data.var_data();
        hcl_data.report().verify_report_data(var_data)?;

        let claim = parse_tee_evidence(snp_report);
        Ok(claim)
    }
}

fn verify_quote(quote: &Quote, hcl_data: &HclData, hashed_nonce: &[u8]) -> Result<()> {
    let ak_pub = hcl_data.var_data().ak_pub()?;

    ak_pub
        .verify_quote(quote, hashed_nonce)
        .context("Failed to verify vTPM quote")?;

    Ok(())
}

fn verify_snp_report(snp_report: &AttestationReport, vcek: &Vcek) -> Result<()> {
    let vcek_data = vcek.0.to_der().context("Failed to get raw VCEK data")?;
    let cert_chain = [CertTableEntry::new(CertType::VCEK, vcek_data)];
    verify_report_signature(snp_report, &cert_chain)?;

    if snp_report.vmpl != HCL_VMPL_VALUE {
        return Err(anyhow!("VMPL of SNP report is not {HCL_VMPL_VALUE}"));
    }

    Ok(())
}

fn nonced_pub_key_hash(attestation: &Attestation, nonce: &str) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(nonce);
    hasher.update(&attestation.tee_pubkey.k_mod);
    hasher.update(&attestation.tee_pubkey.k_exp);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_snp_report() {
        let report = include_bytes!("../../../../test_data/az-hcl-data.bin");
        let hcl_data: HclData = report.as_slice().try_into().unwrap();
        let vcek = Vcek::from_pem(include_str!("../../../../test_data/az-vcek.pem")).unwrap();
        verify_snp_report(hcl_data.report().snp_report(), &vcek).unwrap();

        let mut wrong_report = *report;

        // messing with snp report
        wrong_report[0x00b0] = 0;
        let wrong_hcl_data: HclData = wrong_report.as_slice().try_into().unwrap();
        verify_snp_report(wrong_hcl_data.report().snp_report(), &vcek).unwrap_err();
    }

    #[test]
    fn test_verify_quote() {
        let signature = include_bytes!("../../../../test_data/az-vtpm-quote-sig.bin").to_vec();
        let message = include_bytes!("../../../../test_data/az-vtpm-quote-msg.bin").to_vec();
        let quote = Quote { signature, message };
        let report = include_bytes!("../../../../test_data/az-hcl-data.bin");
        let hcl_data: HclData = report.as_slice().try_into().unwrap();
        let nonce = "challenge".as_bytes();
        verify_quote(&quote, &hcl_data, nonce).unwrap();

        let signature = quote.signature.clone();
        let mut wrong_message = quote.message.clone();
        wrong_message.reverse();
        let wrong_quote = Quote {
            signature,
            message: wrong_message,
        };
        verify_quote(&wrong_quote, &hcl_data, nonce).unwrap_err();

        let wrong_nonce = "wrong".as_bytes();
        verify_quote(&quote, &hcl_data, wrong_nonce).unwrap_err();

        let mut wrong_report = *report;
        // messing with AKpub in var data
        wrong_report[0x0540] = 0;
        let wrong_hcl_data: HclData = wrong_report.as_slice().try_into().unwrap();
        verify_quote(&quote, &wrong_hcl_data, nonce).unwrap_err();
    }
}
