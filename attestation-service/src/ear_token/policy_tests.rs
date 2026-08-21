// Copyright (c) 2026 Overclock Labs Inc.
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context};
use policy_engine::rego::{Regorus, RegorusExtension};
use rstest::rstest;
use serde_json::{json, Value};

const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";

fn reference_extension(reference_values: Value) -> RegorusExtension {
    RegorusExtension {
        name: "query_reference_value".to_string(),
        id: 1,
        extension: Box::new(move |params: Vec<regorus::Value>| {
            if params.len() != 1 {
                bail!("query_reference_value requires one parameter");
            }
            let id = params[0]
                .as_string()
                .context("reference value id must be a string")?;
            let value = reference_values
                .get(id.as_ref())
                .cloned()
                .unwrap_or(Value::Null);
            Ok(serde_json::from_value(value)?)
        }),
    }
}

async fn evaluate(claims: Value, reference_values: Value) -> Value {
    let result = Regorus::default()
        .evaluate(
            None,
            json!({"nvidia": claims}).to_string(),
            include_str!("ear_default_policy_gpu.rego").to_string(),
            vec![TRUST_CLAIMS_RULE.to_string()],
            vec![reference_extension(reference_values)],
        )
        .await
        .unwrap();

    result.eval_rules_result[TRUST_CLAIMS_RULE].clone().unwrap()
}

fn local_reference_values(claims: &Value) -> Value {
    json!({
        "allowed_driver_versions": [claims["config"]["driver_version"].clone()],
        "allowed_vbios_versions": [claims["config"]["vbios_version"].clone()],
        "allowed_gpu_fwids": [claims["config"]["fwid"].clone()],
        "allowed_gpu_measurements": {
            "1": claims["measurements"]["1"].clone(),
        },
    })
}

fn local_claims(claims: &str) -> Value {
    let mut claims: Value = serde_json::from_str(claims).unwrap();
    claims["verifier"] = json!("local");
    claims
}

#[rstest]
#[case::hopper(include_str!(
    "../../../deps/verifier/test_data/nvidia/hopperAttestationReport-claims.txt"
))]
#[case::blackwell(include_str!(
    "../../../deps/verifier/test_data/nvidia/blackwellAttestationReport-claims.txt"
))]
#[tokio::test]
async fn local_policy_uses_architecture_neutral_references(#[case] claims: &str) {
    let claims = local_claims(claims);
    let trust = evaluate(claims.clone(), local_reference_values(&claims)).await;

    assert_eq!(trust["hardware"], 2);
    assert_eq!(trust["configuration"], 2);
    assert_eq!(trust["executables"], 3);
}

#[tokio::test]
async fn local_measurement_mismatch_is_not_affirming() {
    let claims = local_claims(include_str!(
        "../../../deps/verifier/test_data/nvidia/blackwellAttestationReport-claims.txt"
    ));
    let mut reference_values = local_reference_values(&claims);
    reference_values["allowed_gpu_measurements"]["1"] = json!("not-an-approved-digest");

    let trust = evaluate(claims, reference_values).await;

    assert_eq!(trust["hardware"], 2);
    assert_eq!(trust["configuration"], 2);
    assert_eq!(trust["executables"], 33);
}

#[tokio::test]
async fn verifier_claim_selects_policy_path() {
    let mut remote = json!({
        "verifier": "remote",
        "x-nvidia-gpu-attestation-report-cert-chain": {
            "x-nvidia-cert-ocsp-status": "good",
            "x-nvidia-cert-status": "valid",
        },
        "x-nvidia-gpu-attestation-report-cert-chain-fwid-match": true,
        "x-nvidia-gpu-attestation-report-parsed": true,
        "x-nvidia-gpu-attestation-report-signature-verified": true,
        "x-nvidia-gpu-arch-check": true,
    });
    let trust = evaluate(remote.clone(), json!({})).await;
    assert_eq!(trust["hardware"], 2);

    remote["verifier"] = json!("local");
    let trust = evaluate(remote, json!({})).await;
    assert_eq!(trust["hardware"], 97);

    let mut local = local_claims(include_str!(
        "../../../deps/verifier/test_data/nvidia/blackwellAttestationReport-claims.txt"
    ));
    let trust = evaluate(local.clone(), local_reference_values(&local)).await;
    assert_eq!(trust["hardware"], 2);

    local["verifier"] = json!("remote");
    let trust = evaluate(local, json!({})).await;
    assert_eq!(trust["hardware"], 97);
}
