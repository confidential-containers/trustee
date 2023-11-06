// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use serde_json::{Map, Value};
use serde_variant::to_variant_name;

use crate::verifier::TeeEvidenceParsedClaim;

/// This funciton will transpose the following structured json
/// ```json
/// {
///     "a" : {
///         "b": "c"
///     },
///     "d": "e"
/// }
/// ```
/// into a flatten one with '.' to separate, s.t.
/// ```json
/// {
///     "a.b": "c",
///     "d": "e"
/// }
/// ```
pub fn flatten_claims(
    tee: kbs_types::Tee,
    claims: &TeeEvidenceParsedClaim,
) -> Result<TeeEvidenceParsedClaim> {
    let mut map = Map::new();
    let tee_type = to_variant_name(&tee)?;
    match claims {
        Value::Object(obj) => {
            for (k, v) in obj {
                flatten_helper(&mut map, v, format!("{tee_type}.{}", k.clone()));
            }
        }
        _ => bail!("input claims must be a map"),
    }

    Ok(serde_json::Value::Object(map))
}

/// Recursion algorithm helper of `flatten_claims`
fn flatten_helper(parent: &mut Map<String, Value>, child: &serde_json::Value, prefix: String) {
    match child {
        Value::Null => {
            let _ = parent.insert(prefix, Value::Null);
        }
        Value::Bool(v) => {
            let _ = parent.insert(prefix, Value::Bool(*v));
        }
        Value::Number(v) => {
            let _ = parent.insert(prefix, Value::Number(v.clone()));
        }
        Value::String(str) => {
            let _ = parent.insert(prefix, Value::String(str.clone()));
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                let sub_prefix = format!("{prefix}.{i}");
                flatten_helper(parent, v, sub_prefix);
            }
        }
        Value::Object(obj) => {
            for (k, v) in obj {
                let sub_prefix = format!("{prefix}.{k}");
                flatten_helper(parent, v, sub_prefix);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use super::flatten_claims;

    #[test]
    fn flatten() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": null
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
        });
        let flatten = flatten_claims(kbs_types::Tee::Tdx, &json).expect("flatten failed");
        let expected = json!({
                "tdx.ccel.kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "tdx.ccel.kernel_parameters.console": "hvc0",
                "tdx.ccel.kernel_parameters.root": "/dev/vda1",
                "tdx.ccel.kernel_parameters.rw": null,
                "tdx.quote.header.version": "0400",
                "tdx.quote.header.att_key_type": "0200",
                "tdx.quote.header.tee_type": "81000000",
                "tdx.quote.header.reserved": "00000000",
                "tdx.quote.header.vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                "tdx.quote.header.user_data": "d099bfec0a477aa85a605dceabf2b10800000000",
                "tdx.quote.body.mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                "tdx.quote.body.mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "tdx.quote.body.seam_attributes": "0000000000000000",
                "tdx.quote.body.td_attributes": "0100001000000000",
                "tdx.quote.body.mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                "tdx.quote.body.tcb_svn": "03000500000000000000000000000000",
                "tdx.quote.body.xfam": "e742060000000000"
        });
        assert_json_eq!(expected, flatten);
    }
}
