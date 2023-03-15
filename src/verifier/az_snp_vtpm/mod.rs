// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attestation, TeeEvidenceParsedClaim, Verifier};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use az_snp_vtpm::certs::{get_chain_from_amd, get_vcek_from_amd};
use az_snp_vtpm::hcl::{buf_to_hcl_data, HclReportWithRuntimeData};
use az_snp_vtpm::report::Validateable;
use az_snp_vtpm::vtpm::{Quote, VerifyVTpmQuote};
use openssl::sha::sha256;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

const HCL_VMPL_VALUE: u32 = 0;

#[derive(Serialize, Deserialize)]
struct Evidence {
    quote: Quote,
    report: Vec<u8>,
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

        let hcl_report: HclReportWithRuntimeData = evidence.report[..].try_into()?;
        let hashed_quote = hash_quote(attestation, &nonce);

        verify_quote(&evidence.quote, &hcl_report, &hashed_quote)?;
        verify_snp_report(&hcl_report)?;
        verify_report_data(&hcl_report, &evidence.report)?;

        let claim = parse_tee_evidence(&hcl_report);
        Ok(claim)
    }
}

fn verify_report_data(report: &HclReportWithRuntimeData, bytes: &[u8]) -> Result<()> {
    let (_, var_data) = buf_to_hcl_data(bytes)?;
    let var_data_hash = sha256(var_data);

    // Only the first 32 bytes of SNP report data are used for the sha256
    let report_data = &report.snp_report().report_data[..32];

    if var_data_hash != report_data {
        return Err(anyhow!(
            "SNP report data field is not matching runtime data"
        ));
    }

    Ok(())
}

fn verify_quote(
    quote: &Quote,
    report: &HclReportWithRuntimeData,
    hashed_nonce: &[u8],
) -> Result<()> {
    let ak_pub = report.get_attestation_key()?;

    let result = ak_pub
        .verify_quote(quote, Some(hashed_nonce))
        .context("Failed to verify vTPM quote")?;

    if !result {
        return Err(anyhow!("vTPM quote is invalid"));
    }
    Ok(())
}

fn parse_tee_evidence(hcl_report: &HclReportWithRuntimeData) -> TeeEvidenceParsedClaim {
    let report = hcl_report.snp_report();
    let numbers = [
        ("policy_abi_major", report.policy.abi_major()),
        ("policy_abi_minor", report.policy.abi_minor()),
        ("policy_smt_allowed", report.policy.smt_allowed()),
        ("policy_migrate_ma", report.policy.migrate_ma_allowed()),
        ("policy_debug_allowed", report.policy.debug_allowed()),
        (
            "policy_single_socket",
            report.policy.single_socket_required(),
        ),
        // versioning info
        (
            "reported_tcb_bootloader",
            report.reported_tcb.boot_loader as u64,
        ),
        ("reported_tcb_tee", report.reported_tcb.tee as u64),
        ("reported_tcb_snp", report.reported_tcb.snp as u64),
        (
            "reported_tcb_microcode",
            report.reported_tcb.microcode as u64,
        ),
        // platform info
        ("platform_tsme_enabled", report.plat_info.tsme_enabled()),
        ("platform_smt_enabled", report.plat_info.smt_enabled()),
    ];

    let mut string_map: BTreeMap<_, _> = numbers.iter().map(|(k, v)| (*k, v.to_string())).collect();
    string_map.insert("measurement", base64::encode(report.measurement));

    json!(string_map) as TeeEvidenceParsedClaim
}

fn verify_snp_report(report: &HclReportWithRuntimeData) -> Result<()> {
    let snp_report = report.snp_report();
    let vcek = get_vcek_from_amd(snp_report)?;
    let cert_chain = get_chain_from_amd()?;

    cert_chain.validate()?;
    vcek.validate(&cert_chain)?;
    snp_report.validate(&vcek)?;

    if snp_report.vmpl != HCL_VMPL_VALUE {
        return Err(anyhow!("VMPL of SNP report is not 0"));
    }

    Ok(())
}

fn hash_quote(attestation: &Attestation, nonce: &str) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(nonce);
    hasher.update(&attestation.tee_pubkey.k_mod);
    hasher.update(&attestation.tee_pubkey.k_exp);
    hasher.finalize().to_vec()
}
