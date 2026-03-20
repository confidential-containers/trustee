use anyhow::*;
use kbs_types::TeePubKey;
use serde::Deserialize;
use serde_json::Value;
use tracing::info;

#[cfg(feature = "coco-as-grpc")]
pub(crate) mod grpc;

#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
pub(crate) mod builtin;

pub const TOKEN_TEE_PUBKEY_PATH_COCO: &str = "/customized_claims/runtime_data/tee-pubkey";
pub const TOKEN_TEE_PUBKEY_PATH_EAR: &str =
    "/submods/cpu0/ear.veraison.annotated-evidence/runtime_data_claims/tee-pubkey";

pub fn parse_token_claims(claims: Value) -> Result<(TeePubKey, bool)> {
    if let Some(pkey_value) = claims.pointer(TOKEN_TEE_PUBKEY_PATH_COCO) {
        let tee_pubkey =
            TeePubKey::deserialize(pkey_value).context("Failed to deserialize tee public key")?;
        info!("Found a legacy COCO AS token with Simple format. Suggesting to use EAR format instead and the simple format has already been deprecated.");
        return Ok((tee_pubkey, true));
    } else if let Some(pkey_value) = claims.pointer(TOKEN_TEE_PUBKEY_PATH_EAR) {
        let tee_pubkey =
            TeePubKey::deserialize(pkey_value).context("Failed to deserialize tee public key")?;
        let mut allowed = true;
        let submods = match claims.get("submods").and_then(Value::as_object) {
            Some(obj) => obj,
            None => bail!("No submods found in claims"),
        };

        for (_name, submod) in submods {
            let status = submod.get("ear.status").and_then(Value::as_str);
            if status != Some("affirming") {
                allowed = false;
            }
        }

        return Ok((tee_pubkey, allowed));
    }
    bail!("No tee public key found in claims");
}
