// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{InitDataHash, ReportData};

use super::{TeeEvidenceParsedClaim, Verifier};
use crate::snp::{
    load_milan_cert_chain, parse_tee_evidence, verify_report_signature, VendorCertificates,
};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use az_snp_vtpm::certs::Vcek;
use az_snp_vtpm::hcl::HclData;
use az_snp_vtpm::vtpm::{Quote, VerifyVTpmQuote};
use log::warn;
use serde::{Deserialize, Serialize};
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};

const HCL_VMPL_VALUE: u32 = 0;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: Quote,
    report: Vec<u8>,
    vcek: String,
}

pub struct AzSnpVtpm {
    vendor_certs: VendorCertificates,
}

impl AzSnpVtpm {
    pub fn new() -> Result<Self> {
        let Result::Ok(vendor_certs) = load_milan_cert_chain() else {
            bail!("Failed to load Milan cert chain");
        };
        let vendor_certs = vendor_certs.clone();
        Ok(Self { vendor_certs })
    }
}

#[async_trait]
impl Verifier for AzSnpVtpm {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let ReportData::Value(expected_report_data) = expected_report_data else {
            bail!("unexpected empty report data");
        };

        if let InitDataHash::Value(_) = expected_init_data_hash {
            warn!("Azure SNP vTPM verifier does not support verify init data hash, will ignore the input `init_data_hash`.");
        }

        let evidence = serde_json::from_slice::<Evidence>(evidence)
            .context("Failed to deserialize Azure vTPM SEV-SNP evidence")?;

        let hcl_data: HclData = evidence.report[..].try_into()?;
        let snp_report = hcl_data.report().snp_report();
        let vcek = Vcek::from_pem(&evidence.vcek)?;

        verify_quote(&evidence.quote, &hcl_data, expected_report_data)?;
        verify_snp_report(snp_report, &vcek, &self.vendor_certs)?;

        let var_data = hcl_data.var_data();
        hcl_data.report().verify_report_data(var_data)?;

        let claim = parse_tee_evidence(snp_report);
        Ok(claim)
    }
}

fn verify_quote(quote: &Quote, hcl_data: &HclData, report_data: &[u8]) -> Result<()> {
    let ak_pub = hcl_data.var_data().ak_pub()?;

    ak_pub
        .verify_quote(quote, report_data)
        .context("Failed to verify vTPM quote")?;

    Ok(())
}

fn verify_snp_report(
    snp_report: &AttestationReport,
    vcek: &Vcek,
    vendor_certs: &VendorCertificates,
) -> Result<()> {
    let vcek_data = vcek.0.to_der().context("Failed to get raw VCEK data")?;
    let cert_chain = [CertTableEntry::new(CertType::VCEK, vcek_data)];
    verify_report_signature(snp_report, &cert_chain, vendor_certs)?;

    if snp_report.vmpl != HCL_VMPL_VALUE {
        bail!("VMPL of SNP report is not {HCL_VMPL_VALUE}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_snp_report() {
        let report = include_bytes!("../../test_data/az-hcl-data.bin");
        let hcl_data: HclData = report.as_slice().try_into().unwrap();
        let vcek = Vcek::from_pem(include_str!("../../test_data/az-vcek.pem")).unwrap();
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_snp_report(hcl_data.report().snp_report(), &vcek, vendor_certs).unwrap();

        let mut wrong_report = *report;

        // messing with snp report
        wrong_report[0x00b0] = 0;
        let wrong_hcl_data: HclData = wrong_report.as_slice().try_into().unwrap();
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_snp_report(wrong_hcl_data.report().snp_report(), &vcek, vendor_certs).unwrap_err();
    }

    #[test]
    fn test_verify_quote() {
        let signature = include_bytes!("../../test_data/az-vtpm-quote-sig.bin").to_vec();
        let message = include_bytes!("../../test_data/az-vtpm-quote-msg.bin").to_vec();
        let quote = Quote { signature, message };
        let report = include_bytes!("../../test_data/az-hcl-data.bin");
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
