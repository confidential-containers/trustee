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

    // The custom claims are the policy-defined extensions that the CoCo AS
    // attaches to each appraisal (submodule). In the token JSON they are
    // flattened into each submodule alongside the standard `ear.*` claims, so
    // collect every non-`ear.` key per submodule, keyed by submodule name.
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

    // Retain the standard `ear.*` claims of each appraisal (submodule), keyed
    // by submodule name. This is what advanced policies can drill into (e.g.
    // status, trustworthiness vector or annotated evidence per submodule).
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
            // The CoCo AS is multi-TEE and the concrete TEE type is not
            // exposed at this layer, so it is left unspecified here.
            tee_type: Vec::new(),
            policy_ids: vec!["default".to_string()],
            issuer,
            verification_result,
            claims: ear_claims,
        },
        tee_pubkey,
        custom_claims,
    })
}
