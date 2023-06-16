// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use as_types::TeeEvidenceParsedClaim;
use serde_json::{Map, Value};

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
pub fn flatten_claims(claims: &TeeEvidenceParsedClaim) -> Result<TeeEvidenceParsedClaim> {
    let mut map = Map::new();
    match claims {
        Value::Object(obj) => {
            for (k, v) in obj {
                flatten_helper(&mut map, v, k.clone());
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
        });
        let flatten = flatten_claims(&json).expect("flatten failed");
        let expected = json!({
                "ccel.kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "ccel.kernel_parameters.console": "hvc0",
                "ccel.kernel_parameters.root": "/dev/vda1",
                "ccel.kernel_parameters.rw": null,
                "quote.mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "quote.mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "quote.mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "quote.mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                "quote.mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "quote.report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "quote.seam_attributes": "0000000000000000",
                "quote.td_attributes": "0100001000000000",
                "quote.mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                "quote.tcb_svn": "03000500000000000000000000000000",
                "quote.xfam": "e742060000000000"
        });
        assert_json_eq!(expected, flatten);
    }
}
