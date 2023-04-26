// Copyright (c) Microsoft Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{Attestation, TeeEvidenceParsedClaim, Verifier};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use az_snp_vtpm::certs::{AmdChain, Vcek, X509};
use az_snp_vtpm::hcl::{HclData, RuntimeData};
use az_snp_vtpm::report::Validateable;
use az_snp_vtpm::vtpm::{Quote, VerifyVTpmQuote};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sev::firmware::guest::types::{AttestationReport, SnpTcbVersion};
use sha2::{Digest, Sha384};
use std::collections::BTreeMap;

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
    let runtime_data: RuntimeData = hcl_data.var_data().try_into()?;
    let ak_pub = runtime_data.get_attestation_key()?;

    ak_pub
        .verify_quote(quote, hashed_nonce)
        .context("Failed to verify vTPM quote")?;

    Ok(())
}

fn build_amd_chain() -> Result<AmdChain> {
    let bytes = include_bytes!("./milan_ask_ark.pem");
    let certs = X509::stack_from_pem(bytes)?;
    let ask = certs[0].clone();
    let ark = certs[1].clone();
    let chain = AmdChain { ask, ark };
    Ok(chain)
}

fn verify_snp_report(snp_report: &AttestationReport, vcek: &Vcek) -> Result<()> {
    let amd_chain = build_amd_chain()?;

    amd_chain
        .validate()
        .context("Verification of AMD certificate chain failed")?;
    vcek.validate(&amd_chain)
        .context("Verification of VCEK evidence failed")?;
    snp_report
        .validate(vcek)
        .context("Verification of SEV-SNP report failed")?;

    if snp_report.vmpl != HCL_VMPL_VALUE {
        return Err(anyhow!("VMPL of SNP report is not {HCL_VMPL_VALUE}"));
    }

    Ok(())
}

fn parse_tee_evidence(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let SnpTcbVersion {
        boot_loader,
        tee,
        snp,
        microcode,
        ..
    } = report.reported_tcb;
    let policy = report.policy;

    let num_values = [
        ("policy_abi_major", policy.abi_major()),
        ("policy_abi_minor", policy.abi_minor()),
        ("policy_smt_allowed", policy.smt_allowed()),
        ("policy_migrate_ma", policy.migrate_ma_allowed()),
        ("policy_debug_allowed", policy.debug_allowed()),
        ("policy_single_socket", policy.single_socket_required()),
        // versioning info
        ("reported_tcb_bootloader", boot_loader as u64),
        ("reported_tcb_tee", tee as u64),
        ("reported_tcb_snp", snp as u64),
        ("reported_tcb_microcode", microcode as u64),
        // platform info
        ("platform_tsme_enabled", report.plat_info.tsme_enabled()),
        ("platform_smt_enabled", report.plat_info.smt_enabled()),
    ];

    let mut string_map: BTreeMap<_, _> = num_values
        .iter()
        .map(|(k, v)| (*k, v.to_string()))
        .collect();
    string_map.insert("measurement", base64::encode(report.measurement));

    json!(string_map) as TeeEvidenceParsedClaim
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
        let report = include_bytes!("../../../test_data/az-hcl-data.bin");
        let hcl_data: HclData = report.as_slice().try_into().unwrap();
        let vcek = Vcek::from_pem(include_str!("../../../test_data/az-vcek.pem")).unwrap();
        verify_snp_report(hcl_data.report().snp_report(), &vcek).unwrap();

        let mut wrong_report = *report;
        // messing with snp report
        wrong_report[0x00b0] = 0;
        let wrong_hcl_data: HclData = wrong_report.as_slice().try_into().unwrap();
        verify_snp_report(wrong_hcl_data.report().snp_report(), &vcek).unwrap_err();
    }

    #[test]
    fn test_verify_quote() {
        let signature = include_bytes!("../../../test_data/az-vtpm-quote-sig.bin").to_vec();
        let message = include_bytes!("../../../test_data/az-vtpm-quote-msg.bin").to_vec();
        let quote = Quote { signature, message };
        let report = include_bytes!("../../../test_data/az-hcl-data.bin");
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

    #[test]
    fn test_parse_evidence() {
        let report = include_bytes!("../../../test_data/az-hcl-data.bin");
        let hcl_data: HclData = report.as_slice().try_into().unwrap();
        let snp_report = hcl_data.report().snp_report();
        let claim = parse_tee_evidence(snp_report);

        let reference = json!({
          "measurement": "ofOTBBMke7OM/BcVeeo8EtX+SQHwx5L2P9ddmPHvgnwjUAZE4OaS5r6Rf5BQ09OM",
          "platform_smt_enabled": "0",
          "platform_tsme_enabled": "1",
          "policy_abi_major": "0",
          "policy_abi_minor": "31",
          "policy_debug_allowed": "0",
          "policy_migrate_ma": "0",
          "policy_single_socket": "0",
          "policy_smt_allowed": "1",
          "reported_tcb_bootloader": "3",
          "reported_tcb_microcode": "115",
          "reported_tcb_snp": "8",
          "reported_tcb_tee": "0"
        });
        assert!(claim == reference);
    }
}
