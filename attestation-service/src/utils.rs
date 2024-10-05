// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use ear::RawValue;
use kbs_types::Tee;
use serde_json::Value;
use serde_variant::to_variant_name;
use std::collections::BTreeMap;

/// Transform TCB claims from format returned by verifiers to format
/// provided to the policy engine and included in the EAR token.
///
/// This function does three things.
///
/// 1) If the input claims include an init_data claim (meaning that
///    the verifier has validated the init_data), add the JSON
///    init_data_claims to the output claims. Do the same thing
///    for the report_data and runtime_data_claims.
///
///    This means that the full init_data and report_data will be
///    available in the token.
///
/// 2) Move all claims from input_claims except the ones mentioned
///    in the previous step into their own Object under the tee name.
///
/// 3) Convert the claims from serde_json Values to RawValues from the
///    EAR crate.
///
pub fn transform_claims(
    mut input_claims: Value,
    init_data_claims: Value,
    runtime_data_claims: Value,
    tee: Tee,
) -> Result<BTreeMap<String, RawValue>> {
    let mut output_claims = BTreeMap::new();

    // If the verifier produces an init_data claim (meaning that
    // it has validated the init_data hash), add the JSON init_data_claims,
    // to the claims map. Do the same for the report data.
    //
    // These claims will be flattened and provided to the policy engine.
    // They will also end up in the EAR token as part of the annotated evidence.
    if let Some(claims_map) = input_claims.as_object_mut() {
        if let Some(init_data) = claims_map.remove("init_data") {
            output_claims.insert(
                "init_data".to_string(),
                RawValue::Text(init_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&init_data_claims)?)?;
            output_claims.insert("init_data_claims".to_string(), transformed_claims);
        }

        if let Some(report_data) = claims_map.remove("report_data") {
            output_claims.insert(
                "report_data".to_string(),
                RawValue::Text(report_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&runtime_data_claims)?)?;
            output_claims.insert("runtime_data_claims".to_string(), transformed_claims);
        }
    }

    let transformed_claims: RawValue =
        serde_json::from_str(&serde_json::to_string(&input_claims)?)?;
    output_claims.insert(to_variant_name(&tee)?.to_string(), transformed_claims);

    Ok(output_claims)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use kbs_types::Tee;
    use serde_json::{json, Value};

    use super::transform_claims;

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
        let transformed_claims =
            transform_claims(json, init_data_claims, runtime_data_claims, Tee::Tdx)
                .expect("flatten failed");

        let expected_claims = json!({
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

        assert_json_eq!(expected_claims, transformed_claims);
    }
}
