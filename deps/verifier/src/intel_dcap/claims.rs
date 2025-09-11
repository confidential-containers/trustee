use intel_tee_quote_verification_rs::{sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t};
use serde_json::{Map, Number, Value};
use std::ffi::CStr;
use std::os::raw::c_char;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

struct SgxQlQvResultWrapper(pub sgx_ql_qv_result_t);

/// Wrapper for mapping enum response code to simple string.
/// TerminalStatus is special one not visible to end user to fulfill match conditions.
/// Statuses which are applicable for this method are filtered before invocation of prepare_custom_claims_map.
impl SgxQlQvResultWrapper {
    fn as_str(&self) -> Value {
        let mapping = match self.0 {
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => "UpToDate",
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED => "ConfigurationNeeded",
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE => "OutOfDate",
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED => {
                "OutOfDateConfigurationNeeded"
            }
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED => "SWHardeningNeeded",
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
                "ConfigurationAndSWHardeningNeeded"
            }
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED => "TDRelaunchAdvised",
            sgx_ql_qv_result_t::SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED => {
                "TDRelaunchAdvisedConfigurationNeeded"
            }
            _ => "TerminalStatus",
        };

        Value::String(mapping.to_string())
    }
}

pub(crate) fn prepare_custom_claims_map(
    supp_data: &mut sgx_ql_qv_supplemental_t,
    collateral_expiration_status: u32,
    quote_verification_result: sgx_ql_qv_result_t,
) -> Map<String, Value> {
    let mut claims_map = Map::new();

    claims_map.insert(
        "earliest_issue_date".to_string(),
        Value::String(format_rfc3339(supp_data.earliest_issue_date)),
    );
    claims_map.insert(
        "latest_issue_date".to_string(),
        Value::String(format_rfc3339(supp_data.latest_issue_date)),
    );
    claims_map.insert(
        "earliest_expiration_date".to_string(),
        Value::String(format_rfc3339(supp_data.earliest_expiration_date)),
    );
    claims_map.insert(
        "tcb_date".to_string(),
        Value::String(format_rfc3339(supp_data.tcb_level_date_tag)),
    );
    claims_map.insert(
        "pck_crl_num".to_string(),
        Value::from(Number::from(supp_data.pck_crl_num)),
    );
    claims_map.insert(
        "root_ca_crl_num".to_string(),
        Value::from(Number::from(supp_data.root_ca_crl_num)),
    );
    claims_map.insert(
        "tcb_eval_num".to_string(),
        Value::from(Number::from(supp_data.root_ca_crl_num)),
    );
    claims_map.insert(
        "platform_provider_id".to_string(),
        Value::String(hex::encode(supp_data.pck_ppid)),
    );

    claims_map.insert(
        "sgx_type".to_string(),
        Value::String(match supp_data.sgx_type {
            0 => "Standard".to_string(),
            1 => "Scalable".to_string(),
            2 => "Scalable with Integrity".to_string(),
            other => format!("Unknown ({})", other),
        }),
    );
    if supp_data.sgx_type > 0 {
        claims_map.insert(
            "is_dynamic_platform".to_string(),
            Value::Bool(supp_data.dynamic_platform == 1),
        );
        claims_map.insert(
            "is_cached_keys".to_string(),
            Value::Bool(supp_data.cached_keys == 1),
        );
        claims_map.insert(
            "is_smt_enabled".to_string(),
            Value::Bool(supp_data.smt_enabled == 1),
        );
    }
    claims_map.insert(
        "root_key_id".to_string(),
        Value::String(hex::encode(supp_data.root_key_id)),
    );

    claims_map.insert(
        "tcb_status".to_string(),
        SgxQlQvResultWrapper(quote_verification_result).as_str(),
    );
    claims_map.insert(
        "collateral_expiration_status".to_string(),
        Value::String(collateral_expiration_status.to_string()),
    );
    claims_map.insert("advisory_ids".to_string(), get_sa_list(&supp_data.sa_list));
    claims_map
}

fn get_sa_list(sa_list: &[c_char; 320]) -> Value {
    let c_str = unsafe { CStr::from_ptr(sa_list.as_ptr()) };

    let advisory_ids = c_str.to_string_lossy();

    if advisory_ids.is_empty() {
        return Value::Array(vec![]);
    }

    advisory_ids
        .split(',')
        .map(|s| Value::String(s.to_string()))
        .collect()
}

fn format_rfc3339(timestamp: i64) -> String {
    OffsetDateTime::from_unix_timestamp(timestamp)
        .expect("invalid unix timestamp.")
        .format(&Rfc3339)
        .expect("failed to format timestamp.")
}

#[cfg(test)]
mod tests {
    use super::prepare_custom_claims_map;
    use assert_json_diff::assert_json_eq;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use intel_tee_quote_verification_rs::{sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t};
    use serde_json::json;

    #[test]
    fn parse_supplemental_data() {
        let supplemental_data =
            "AwADAAAAAAA2owJbAAAAAHAtq2gAAAAAbbbSaAAAAACA7PBlAAAAAAEAAAABAAAAEQAAA\
        EbkA7008Fo/KBerm63KrMf/yY4PJhAIzTDa6TbKzhjV3PWO7zFGNhPeFXDVFiAJkyfg6mPFvHZoUiXGOj2EQXAHBw\
        ICAwEAAwAAAAAAAAAACwAAAAAAAAABsNXfABIi8QI8B6FCx2f9QgAAAAEAAAABAAAAAQAAAAAAAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\
        AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADajAlsAAAAAbNUZaAAAAADs4ER1AAAA\
        AIDs8GUAAAAAEQAAAAAAAAA=";

        let mut supp = deserialize_supp_data(supplemental_data);

        let claims =
            prepare_custom_claims_map(&mut supp, 0, sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK);

        let expected = json!({
          "advisory_ids": [],
          "collateral_expiration_status": "0",
          "earliest_expiration_date": "2025-09-23T15:02:05Z",
          "earliest_issue_date": "2018-05-21T10:45:10Z",
          "is_cached_keys": true,
          "is_dynamic_platform": true,
          "is_smt_enabled": true,
          "latest_issue_date": "2025-08-24T15:19:12Z",
          "pck_crl_num": 1,
          "platform_provider_id": "27e0ea63c5bc76685225c63a3d844170",
          "root_ca_crl_num": 1,
          "root_key_id": "46e403bd34f05a3f2817ab9badcaacc7ffc98e0f261008cd30dae936cace18d5dcf58eef31463613de1570d516200993",
          "sgx_type": "Scalable",
          "tcb_date": "2024-03-13T00:00:00Z",
          "tcb_eval_num": 1,
          "tcb_status": "UpToDate"
        });

        assert_json_eq!(expected, claims);
    }

    fn deserialize_supp_data(encoded: &str) -> sgx_ql_qv_supplemental_t {
        let decoded = STANDARD.decode(encoded).expect("invalid base64");

        assert_eq!(decoded.len(), size_of::<sgx_ql_qv_supplemental_t>());

        let mut supp: sgx_ql_qv_supplemental_t = unsafe { std::mem::zeroed() };
        unsafe {
            std::ptr::copy_nonoverlapping(
                decoded.as_ptr(),
                &mut supp as *mut _ as *mut u8,
                decoded.len(),
            );
        }

        supp
    }
}
