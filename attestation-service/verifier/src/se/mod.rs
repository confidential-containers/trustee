// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use async_trait::async_trait;
use anyhow::anyhow;
use base64::prelude::*;
use serde_json::json;
use crate::{InitDataHash, ReportData};
use crate::se::seattest::FakeSeAttest;
use crate::se::seattest::SeFakeVerifier;

pub mod seattest;

#[derive(Debug, Default)]
pub struct SeVerifier {}

#[async_trait]
impl Verifier for SeVerifier {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {

        verify_evidence(evidence, expected_report_data, expected_init_data_hash)
        .await
        .map_err(|e| anyhow!("Se Verifier: {:?}", e))
    }

    async fn generate_challenge_extra_params(
        &self,
    ) -> Result<String> {

        // TODO replace FakeSeAttest with real crate
        let attester = FakeSeAttest::default();

        let hkds: Vec<String> = vec![String::new(); 2];
        let certk = "cert_file_path";
        let signk = "sign_file_path";
        let arpk = "arpk_file_path";

        let extra_params = attester.create(hkds, certk, signk, arpk)
                            .await
                            .context("Create SE attestation request failed: {:?}")?;

        Ok(BASE64_STANDARD.encode(extra_params))
    }
}

async fn verify_evidence(
    evidence: &[u8],
    _expected_report_data: &ReportData<'_>,
    _expected_init_data_hash: &InitDataHash<'_>,
) -> Result<TeeEvidenceParsedClaim> {
    // TODO replace FakeSeAttest with real crate
    let attester = FakeSeAttest::default();

    let arpk = "arpk_file_path";
    let hdr = "hdr_file_path";
    let se = attester.verify(evidence, arpk, hdr)
                .await
                .context("Verify SE attestation evidence failed: {:?}")?;

    let claims_map = json!({
        "serial_number": format!("{}", "SE-ID"),
        "measurement": format!("{}", BASE64_STANDARD.encode(se.clone())),
        "report_data": format!("{}", BASE64_STANDARD.encode(se.clone())),
    });

    Ok(claims_map as TeeEvidenceParsedClaim)
}