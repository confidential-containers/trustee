// Copyright (c) 2026 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use ear::RawValue;
use kbs_types::Tee;
use serde::Serialize;
use serde_json::Value;
use serde_variant::to_variant_name;

/// EAR draft-04 verifier-authority claims (`ear_verifier_claims`).
///
/// Wire shape (absent optionals omitted):
/// ```json
/// {
///   "runtime_data": { },
///   "init_data": { },
///   "custom": { }
/// }
/// ```
#[derive(Debug, Default, Clone, PartialEq, Serialize)]
pub struct VerifierClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_data: Option<Value>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub custom: BTreeMap<String, Value>,
}

impl VerifierClaims {
    pub fn into_raw_map(self) -> Result<BTreeMap<String, RawValue>> {
        to_raw_map(&self)
    }
}

/// EAR draft-04 attester-authority claims (`ear_attester_claims`).
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
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct AttesterClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    init_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    report_data: Option<String>,
    tee: String,
    claims: Value,
}

impl AttesterClaims {
    pub fn into_raw_map(self) -> Result<BTreeMap<String, RawValue>> {
        to_raw_map(&self)
    }
}

/// Intermediate claim set produced from verifier output.
///
/// Holds domain data as [`Value`]. Callers choose the serialization target:
/// - [`Self::policy_input_json`] — legacy flat layout for OPA
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
        })
    }

    /// Legacy flat JSON for the OPA policy engine.
    ///
    /// Keys: `<tee>`, optional `init_data` / `init_data_claims`, optional
    /// `report_data` / `runtime_data_claims`.
    pub fn policy_input_json(&self) -> Result<String> {
        #[derive(Serialize)]
        struct PolicyInput<'a> {
            #[serde(skip_serializing_if = "Option::is_none")]
            init_data: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            init_data_claims: Option<&'a Value>,
            #[serde(skip_serializing_if = "Option::is_none")]
            report_data: Option<&'a str>,
            #[serde(skip_serializing_if = "Option::is_none")]
            runtime_data_claims: Option<&'a Value>,
            #[serde(flatten)]
            tee: BTreeMap<&'a str, &'a Value>,
        }

        let tee_name = to_variant_name(&self.tee)?;
        let mut tee = BTreeMap::new();
        tee.insert(tee_name, &self.tee_claims);

        serde_json::to_string(&PolicyInput {
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
    ///
    /// `custom` is policy-authored material that [`TransformedClaims`] does not
    /// derive from evidence; the caller must pass it in.
    pub fn verifier_claims(&self, custom: BTreeMap<String, Value>) -> VerifierClaims {
        VerifierClaims {
            init_data: self.init_data_claims.clone(),
            runtime_data: self.runtime_data_claims.clone(),
            custom,
        }
    }
}

fn to_raw_map<T: Serialize>(value: &T) -> Result<BTreeMap<String, RawValue>> {
    Ok(serde_json::from_value(serde_json::to_value(value)?)?)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use super::*;

    #[test]
    fn test_transform_claims() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": ""
                }
            },
            "quote": {
                "header":{
                    "version": "0400",
                    "att_key_type": "0200",
                    "tee_type": "81000000",
                    "reserved": "00000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                    "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                },
                "body":{
                    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                    "seam_attributes": "0000000000000000",
                    "td_attributes": "0100001000000000",
                    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                    "tcb_svn": "03000500000000000000000000000000",
                    "xfam": "e742060000000000"
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });

        let init_data_claims = Value::String("".to_string());
        let runtime_data_claims = Value::String("".to_string());
        let transformed =
            TransformedClaims::new(json, init_data_claims, runtime_data_claims, Tee::Tdx, true)
                .expect("transform failed");

        let expected_policy_input = json!({
            "tdx": {
                "ccel": {
                    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                    "kernel_parameters": {
                        "console": "hvc0",
                        "root": "/dev/vda1",
                        "rw": ""
                    }
                },
                "quote": {
                    "header":{
                        "version": "0400",
                        "att_key_type": "0200",
                        "tee_type": "81000000",
                        "reserved": "00000000",
                        "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                        "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                    },
                    "body":{
                        "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                        "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                        "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                        "seam_attributes": "0000000000000000",
                        "td_attributes": "0100001000000000",
                        "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                        "tcb_svn": "03000500000000000000000000000000",
                        "xfam": "e742060000000000"
                    }
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "runtime_data_claims": "",
            "init_data_claims": ""
        });

        let policy_input: Value =
            serde_json::from_str(&transformed.policy_input_json().unwrap()).unwrap();
        assert_json_eq!(expected_policy_input, policy_input);

        let attester = transformed
            .attester_claims()
            .unwrap()
            .into_raw_map()
            .unwrap();
        assert_eq!(
            attester.get("report_data"),
            Some(&RawValue::String(
                "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429"
                    .to_string()
            ))
        );
        assert_eq!(attester.get("tee"), Some(&RawValue::String("tdx".into())));
        assert!(attester.contains_key("claims"));
        assert!(!attester.contains_key("tdx"));
        assert!(attester.contains_key("init_data"));
        assert!(!attester.contains_key("init_data_claims"));
        assert!(!attester.contains_key("runtime_data_claims"));

        let verifier = transformed
            .verifier_claims(BTreeMap::new())
            .into_raw_map()
            .unwrap();
        assert_eq!(
            verifier.get("init_data"),
            Some(&RawValue::String("".into()))
        );
        assert_eq!(
            verifier.get("runtime_data"),
            Some(&RawValue::String("".into()))
        );
        assert!(!verifier.contains_key("custom"));
    }

    #[test]
    fn test_unbound_plaintext_is_omitted() {
        // A digest-only init-data and raw report-data leave the verifier with
        // nothing to parse, so both parsed claims arrive as `Value::Null`.
        let json = json!({
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656ae",
            "init_data": "0000000000000000000000000000000000000000000000000000000000000000",
            "svn": "1"
        });

        let transformed =
            TransformedClaims::new(json, Value::Null, Value::Null, Tee::Sample, true).unwrap();

        let policy_input: Value =
            serde_json::from_str(&transformed.policy_input_json().unwrap()).unwrap();
        let policy_input = policy_input.as_object().unwrap();
        assert!(!policy_input.contains_key("init_data_claims"));
        assert!(!policy_input.contains_key("runtime_data_claims"));
        // The raw attester values are still reported.
        assert!(policy_input.contains_key("init_data"));
        assert!(policy_input.contains_key("report_data"));

        let verifier = transformed
            .verifier_claims(BTreeMap::new())
            .into_raw_map()
            .unwrap();
        assert!(!verifier.contains_key("init_data"));
        assert!(!verifier.contains_key("runtime_data"));

        let attester = transformed
            .attester_claims()
            .unwrap()
            .into_raw_map()
            .unwrap();
        assert!(attester.contains_key("init_data"));
        assert!(attester.contains_key("report_data"));
        assert_eq!(
            attester.get("tee"),
            Some(&RawValue::String("sample".into()))
        );
        assert!(attester.contains_key("claims"));
        assert!(!attester.contains_key("sample"));
    }
}
