use std::collections::HashSet;

use anyhow::{bail, Context, Result};
use kbs_types::TeePubKey;
use serde::Deserialize;
use serde_json::{Map, Value};
use tracing::warn;

use crate::trust_context::{AttestationSummary, TrustContext};

#[cfg(feature = "coco-as-grpc")]
pub mod grpc;

#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
pub mod builtin;

/// Location of the TEE public key inside a CoCo AS EAR token.
pub const TOKEN_TEE_PUBKEY_PATH_EAR: &str =
    "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/tee-pubkey";

/// Convert a CoCo AS EAR token's claims into a [`TrustContext`]. This is shared
/// by the built-in and gRPC CoCo backends, which consume the same EAR token
/// format. The evidence is considered allowed only if every submodule reports
/// an `ear.status` of `affirming`.
pub fn claims_to_trust_context(claims: Value) -> Result<TrustContext> {
    let Some(pkey_value) = claims.pointer(TOKEN_TEE_PUBKEY_PATH_EAR) else {
        bail!("No tee public key found in claims");
    };
    let tee_pubkey =
        TeePubKey::deserialize(pkey_value).context("Failed to deserialize tee public key")?;

    let submods = claims
        .get("submods")
        .and_then(Value::as_object)
        .context("No submods found in claims")?;
    let verification_result = submods.values().all(|submod| {
        if let Some(status) = submod.get("ear.status").and_then(Value::as_str) {
            if status != "affirming" {
                warn!("CoCo AS submodule {submod} reported a non-affirming status: {status}");
                false
            } else {
                true
            }
        } else {
            warn!("CoCo AS submodule {submod} did not report a status");
            false
        }
    });

    let mut policy_ids = HashSet::new();
    for submod in submods.values() {
        let Some(id) = submod
            .get("ear.appraisal-policy-id")
            .and_then(Value::as_str)
        else {
            continue;
        };
        if !policy_ids.iter().any(|existing| existing == id) {
            policy_ids.insert(id.to_string());
        }
    }

    let policy_ids = policy_ids.into_iter().collect::<Vec<String>>();

    let custom_claims = Value::Object(
        submods
            .iter()
            .map(|(submod_name, appraisal)| {
                let extensions = appraisal
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(key, _)| !key.starts_with("ear."))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Map<String, Value>>();
                (submod_name.clone(), Value::Object(extensions))
            })
            .collect::<Map<String, Value>>(),
    );

    let ear_claims = Value::Object(
        submods
            .iter()
            .map(|(submod_name, appraisal)| {
                let ear = appraisal
                    .as_object()
                    .into_iter()
                    .flatten()
                    .filter(|(key, _)| key.starts_with("ear."))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect::<Map<String, Value>>();
                (submod_name.clone(), Value::Object(ear))
            })
            .collect::<Map<String, Value>>(),
    );

    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    Ok(TrustContext {
        attestation_summary: AttestationSummary {
            tee_type: Vec::new(),
            policy_ids,
            issuer,
            verification_result,
            claims: ear_claims,
        },
        tee_pubkey,
        custom_claims,
    })
}
