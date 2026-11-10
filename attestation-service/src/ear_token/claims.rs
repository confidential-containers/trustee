// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use ear::RawValue;
use kbs_types::Tee;
use serde::Serialize;
use serde_json::Value;
use serde_variant::to_variant_name;
use tracing::trace;

/// EAR draft-04 verifier-authority claims (`ear_verifier_claims`).
///
/// Wire shape (absent optionals omitted):
/// ```json
/// {
///   "runtime_data": { },
///   "init_data": { }
/// }
/// ```
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct VerifierClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<Value>,
}

/// EAR draft-04 attester-authority claims (`ear_attester_claims`) of one device.
///
/// Wire shape (absent optionals omitted):
/// ```json
/// {
///   "tee": "<tee-name>",
///   "claims": { },
///   "report_data": "<raw>",
///   "init_data": "<raw>"
/// }
/// ```
///
/// An appraisal carries a list of these per name of a device, see
/// [`appraisal_attester_claims`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttesterClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    init_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_data: Option<String>,
    tee: String,
    claims: Value,
}

/// Intermediate claim set produced from the verifier output of one device.
///
/// Holds domain data as [`Value`]. Callers choose the serialization target:
/// - [`policy_input_json`] — the `devices` list handed to a policy
/// - [`Self::attester_claims`] / [`Self::verifier_claims`] — EAR-04 maps
#[derive(Debug, Clone)]
pub struct TransformedClaims {
    init_data: Option<String>,
    report_data: Option<String>,
    init_data_claims: Option<Value>,
    runtime_data_claims: Option<Value>,
    /// Hardware / TCB claims with `init_data` / `report_data` removed.
    tee_claims: Value,
    tee: Tee,
    device: String,
}

impl TransformedClaims {
    /// Split verifier output into attester raw strings and verifier-parsed JSON.
    ///
    /// 1. If `input_claims` contains `init_data` (hash validated by the
    ///    verifier), keep the raw string and the parsed `init_data_claims`.
    /// 2. Same for `report_data` / `runtime_data_claims` (optional
    ///    `additional-evidence` stripped when `verbose` is false).
    /// 3. Remaining claims stay under the TEE name in policy input, and under
    ///    `claims` (with `tee` set) on the issued EAR token.
    ///
    /// The verifier yields `Value::Null` for the parsed claims when only a
    /// digest (or raw bytes) was supplied and there was no plaintext to bind.
    /// Those are dropped here so that consumers see an absent key rather than
    /// an explicit `null`.
    pub fn new(
        mut input_claims: Value,
        init_data_claims: Value,
        mut runtime_data_claims: Value,
        tee: Tee,
        device: String,
        verbose: bool,
    ) -> Result<Self> {
        let mut init_data = None;
        let mut report_data = None;
        let mut parsed_init_data = None;
        let mut parsed_runtime_data = None;

        if let Some(claims_map) = input_claims.as_object_mut() {
            if let Some(value) = claims_map.remove("init_data") {
                init_data = Some(
                    value
                        .as_str()
                        .context("init_data claim must be a string")?
                        .to_string(),
                );
                parsed_init_data = (!init_data_claims.is_null()).then_some(init_data_claims);
            }

            if let Some(value) = claims_map.remove("report_data") {
                report_data = Some(
                    value
                        .as_str()
                        .context("report_data claim must be a string")?
                        .to_string(),
                );

                // When attesting environments with lots of devices, the additional
                // evidence can create a token that is very large. This can overwhelm
                // the header size limitation of some http servers (including the KBS).
                // If verbose is false, don't include the additional evidence.
                if !verbose {
                    runtime_data_claims
                        .as_object_mut()
                        .and_then(|map| map.remove("additional-evidence"));
                }

                parsed_runtime_data =
                    (!runtime_data_claims.is_null()).then_some(runtime_data_claims);
            }
        }

        Ok(Self {
            init_data,
            report_data,
            init_data_claims: parsed_init_data,
            runtime_data_claims: parsed_runtime_data,
            tee_claims: input_claims,
            tee,
            device,
        })
    }

    /// Policy input of one device.
    ///
    /// Keys: `device`, `<tee>`, optional `init_data` / `init_data_claims`,
    /// optional `report_data` / `runtime_data_claims`.
    pub fn policy_input(&self) -> Result<Value> {
        #[derive(Serialize)]
        struct PolicyInput<'a> {
            /// Name of the device these claims belong to.
            device: &'a str,

            /// Name of the TEE these claims belong to.
            tee: &'a str,

            /// Claims of the TEE.
            claims: &'a Value,

            /// Raw init data of the device.
            #[serde(skip_serializing_if = "Option::is_none")]
            init_data: Option<&'a str>,

            /// Parsed init data of the device.
            #[serde(skip_serializing_if = "Option::is_none")]
            init_data_claims: Option<&'a Value>,

            /// Raw report data of the device.
            #[serde(skip_serializing_if = "Option::is_none")]
            report_data: Option<&'a str>,

            /// Parsed report data of the device.
            #[serde(skip_serializing_if = "Option::is_none")]
            runtime_data_claims: Option<&'a Value>,
        }

        let tee = to_variant_name(&self.tee)?;

        serde_json::to_value(PolicyInput {
            device: &self.device,
            claims: &self.tee_claims,
            init_data: self.init_data.as_deref(),
            init_data_claims: self.init_data_claims.as_ref(),
            report_data: self.report_data.as_deref(),
            runtime_data_claims: self.runtime_data_claims.as_ref(),
            tee,
        })
        .map_err(Into::into)
    }

    /// Attester-authority claims for `appraisal.attester_claims`.
    pub fn attester_claims(&self) -> Result<AttesterClaims> {
        let tee_name = to_variant_name(&self.tee)?.to_string();

        Ok(AttesterClaims {
            init_data: self.init_data.clone(),
            report_data: self.report_data.clone(),
            tee: tee_name,
            claims: self.tee_claims.clone(),
        })
    }

    /// Verifier-authority claims for `appraisal.verifier_claims`.
    pub fn verifier_claims(&self) -> VerifierClaims {
        VerifierClaims {
            init_data: self.init_data_claims.clone(),
            runtime_data: self.runtime_data_claims.clone(),
        }
    }
}

/// Policy input for a policy that judges `devices` together.
///
/// The shape is the same no matter how many devices a policy accepts:
/// ```json
/// {
///     "devices": [
///         {
///             "device": "nvidia-gpu",
///             "tee": "nvidia",
///             "claims": {},
///             "report_data": "..."
///         },
///         {
///             "device": "tdx",
///             "tee": "tdx",
///             "claims": {},
///             "init_data": "...",
///             "init_data_claims": {},
///             "report_data": "...",
///             "runtime_data_claims": {}
///         },
///         ...
///     ]
/// }
/// ```
pub fn policy_input_json(devices: &[&TransformedClaims]) -> Result<String> {
    let devices = devices
        .iter()
        .map(|device| device.policy_input())
        .collect::<Result<Vec<_>>>()?;

    Ok(serde_json::to_string(&serde_json::json!({
        "devices": devices
    }))?)
}

/// `ear_attester_claims` of an appraisal that judges `devices`.
///
/// The claims are reported under the name of the device, as a list with an
/// entry per device of that name, in the order of `devices`:
/// ```json
/// {
///   "tdx": [
///     { "tee": "tdx", "claims": { } }
///   ],
///   "nvidia-gpu": [
///     { "tee": "nvidia", "claims": { } },
///     { "tee": "nvidia", "claims": { } }
///   ]
/// }
/// ```
/// A node can have several devices of one kind, e.g. GPUs, and they share the
/// name. The value is a list no matter how many there are. Making it depend
/// on the count would change the shape of the token between a node with one
/// GPU and a node with eight, and making it depend on the kind of device
/// would need a list of the devices that can be several, which has no place
/// here.
pub fn appraisal_attester_claims(
    devices: &[&TransformedClaims],
) -> Result<BTreeMap<String, RawValue>> {
    if devices.is_empty() {
        bail!("an appraisal needs at least one device");
    }

    let mut by_name: BTreeMap<&str, Vec<AttesterClaims>> = BTreeMap::new();
    for device in devices {
        by_name
            .entry(&device.device)
            .or_default()
            .push(device.attester_claims()?);
    }

    by_name
        .into_iter()
        .map(|(name, claims)| Ok((name.to_string(), to_raw_value(&claims)?)))
        .collect()
}

/// `ear_verifier_claims` of an appraisal that judges `devices`.
///
/// The init data and the runtime data belong to the request, not to a
/// device, so they are reported once. `devices` lists all the devices of the
/// appraisal, whose evidence has been verified, each name once:
/// ```json
/// {
///   "init_data": { },
///   "runtime_data": { },
///   "devices": ["tdx", "tpm"]
/// }
/// ```
/// Absent optionals are omitted.
///
/// The devices of one request are assumed to agree on both. Not every device
/// has them, so the values are merged key by key: a key that only some of the
/// devices have is kept, and the result is the union of them.
///
/// This is needed because the runtime data of the primary evidence has the
/// key `additional-evidence`, which the runtime data of the additional
/// evidence has not (it is only there if `verbose_token` is set, see
/// [`TransformedClaims::new`]).
///
/// If two devices disagree on the value of a key, there is no way to tell
/// which of them is right, so this fails instead of picking one.
pub fn appraisal_verifier_claims(
    devices: &[&TransformedClaims],
) -> Result<BTreeMap<String, RawValue>> {
    let mut init_data = None;
    let mut runtime_data = None;
    for device in devices {
        merge_request_data(
            &mut init_data,
            device.init_data_claims.as_ref(),
            "init_data",
            &device.device,
        )?;
        merge_request_data(
            &mut runtime_data,
            device.runtime_data_claims.as_ref(),
            "runtime_data",
            &device.device,
        )?;
    }

    let mut claims = BTreeMap::new();
    if let Some(init_data) = init_data {
        claims.insert("init_data".to_string(), to_raw_value(&init_data)?);
    }
    if let Some(runtime_data) = runtime_data {
        claims.insert("runtime_data".to_string(), to_raw_value(&runtime_data)?);
    }
    let mut names: Vec<&str> = Vec::new();
    for device in devices {
        if !names.contains(&device.device.as_str()) {
            names.push(&device.device);
        }
    }
    if !names.is_empty() {
        claims.insert("devices".to_string(), to_raw_value(&names)?);
    }
    Ok(claims)
}

/// Merge the `new` data of `device` into `merged`, see [`appraisal_verifier_claims`].
fn merge_request_data(
    merged: &mut Option<Value>,
    new: Option<&Value>,
    what: &str,
    device: &str,
) -> Result<()> {
    let Some(new) = new else { return Ok(()) };
    let Some(merged) = merged else {
        *merged = Some(new.clone());
        return Ok(());
    };

    match (merged, new) {
        (Value::Object(merged), Value::Object(new)) => {
            for (key, value) in new {
                match merged.get(key) {
                    Some(known) if known != value => bail!(
                        "device `{device}` verified a different `{key}` in the {what} than the other devices"
                    ),
                    Some(_) => trace!(
                        "device `{device}` verified the same `{key}` in the {what} as the other devices"
                    ),
                    None => {
                        merged.insert(key.clone(), value.clone());
                    }
                }
            }
            Ok(())
        }
        (merged, new) if *merged == *new => Ok(()),
        _ => bail!("device `{device}` verified a different {what} than the other devices"),
    }
}

fn to_raw_value<T: Serialize>(value: &T) -> Result<RawValue> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}
