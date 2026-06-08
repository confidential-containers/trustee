use anyhow::Result;
use bitflags::Flags;
use intel_tee_quote_verification_rs::{sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t};
use serde_json::{json, Map, Number, Value};
use std::ffi::CStr;
use std::os::raw::c_char;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::intel_dcap::pck::parse_platform_info;
use crate::intel_dcap::quote::{Quote, QuoteV5Body, QuoteV5Type, TdAttributesFlags};

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
        Value::from(Number::from(supp_data.tcb_eval_ref_num)),
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

fn get_sa_list(sa_list: &[c_char; 450]) -> Value {
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

fn parse_td_attributes(data: &[u8]) -> Result<Map<String, Value>> {
    let arr = <[u8; 8]>::try_from(data)?;
    let td = TdAttributesFlags::from_bits_retain(u64::from_le_bytes(arr));
    let attribs = TdAttributesFlags::FLAGS
        .iter()
        .map(|f| {
            (
                f.name().to_string().to_lowercase(),
                Value::Bool(td.contains(f.value().clone())),
            )
        })
        .collect();

    Ok(attribs)
}

impl Quote {
    pub(crate) fn generate_parsed_claim(&self) -> Result<Map<String, Value>> {
        let claims = match self {
            Quote::V3 { header, body, .. } => {
                // Claims from SGX Quote Header.
                // tee_type encodes the same bytes as att_key_data_0 in the SGX v3 wire format.
                // reserved[0..2] and reserved[2..4] encode qe_svn and pce_svn respectively.
                json!({
                    "header": {
                        "version": hex::encode(header.version),
                        "att_key_type": hex::encode(header.att_key_type),
                        "att_key_data_0": hex::encode(header.tee_type),
                        "qe_svn": hex::encode(&header.reserved[..2]),
                        "pce_svn": hex::encode(&header.reserved[2..]),
                        "vendor_id": hex::encode(header.vendor_id),
                        "user_data": hex::encode(header.user_data),
                    },
                    "body": {
                        "cpu_svn": hex::encode(body.cpu_svn),
                        "misc_select": hex::encode(body.misc_select),
                        "reserved1": hex::encode(body.reserved1),
                        "isv_ext_prod_id": hex::encode(body.isv_ext_prod_id),
                        "attributes.flags": hex::encode(body.attributes_flags),
                        "attributes.xfrm": hex::encode(body.attributes_xfrm),
                        "mr_enclave": hex::encode(body.mr_enclave),
                        "reserved2": hex::encode(body.reserved2),
                        "mr_signer": hex::encode(body.mr_signer),
                        "reserved3": hex::encode(body.reserved3),
                        "config_id": hex::encode(body.config_id),
                        "isv_prod_id": hex::encode(body.isv_prod_id),
                        "isv_svn": hex::encode(body.isv_svn),
                        "config_svn": hex::encode(body.config_svn),
                        "reserved4": hex::encode(body.reserved4),
                        "isv_family_id": hex::encode(body.isv_family_id),
                        "report_data": hex::encode(body.report_data),
                    },
                    "report_data": hex::encode(body.report_data),
                    "init_data": hex::encode(body.config_id),
                })
            }
            Quote::V4 { header, body, .. } => {
                let td_attributes = parse_td_attributes(self.td_attributes())?;
                json!({
                    "quote": {
                        "header": {
                            "version": hex::encode(b"\x04\x00"),
                            "att_key_type": hex::encode(header.att_key_type),
                            "tee_type": hex::encode(header.tee_type),
                            "reserved": hex::encode(header.reserved),
                            "vendor_id": hex::encode(header.vendor_id),
                            "user_data": hex::encode(header.user_data),
                        },
                        "body": {
                            "tcb_svn": hex::encode(body.tcb_svn),
                            "mr_seam": hex::encode(body.mr_seam),
                            "mrsigner_seam": hex::encode(body.mrsigner_seam),
                            "seam_attributes": hex::encode(body.seam_attributes),
                            "td_attributes": hex::encode(body.td_attributes),
                            "xfam": hex::encode(body.xfam),
                            "mr_td": hex::encode(body.mr_td),
                            "mr_config_id": hex::encode(body.mr_config_id),
                            "mr_owner": hex::encode(body.mr_owner),
                            "mr_owner_config": hex::encode(body.mr_owner_config),
                            "rtmr_0": hex::encode(body.rtmr_0),
                            "rtmr_1": hex::encode(body.rtmr_1),
                            "rtmr_2": hex::encode(body.rtmr_2),
                            "rtmr_3": hex::encode(body.rtmr_3),
                            "report_data": hex::encode(body.report_data),
                        },
                    },
                    "report_data": hex::encode(body.report_data),
                    "init_data": hex::encode(body.mr_config_id),
                    "td_attributes": td_attributes,
                })
            }
            Quote::V5 {
                header,
                r#type,
                size,
                body,
                ..
            } => {
                let td_attributes = parse_td_attributes(self.td_attributes())?;
                json!({
                    "quote": {
                        "header": {
                            "version": hex::encode(b"\x05\x00"),
                            "att_key_type": hex::encode(header.att_key_type),
                            "tee_type": hex::encode(header.tee_type),
                            "reserved": hex::encode(header.reserved),
                            "vendor_id": hex::encode(header.vendor_id),
                            "user_data": hex::encode(header.user_data),
                        },
                        "body": match body {
                            QuoteV5Body::Tdx10(body) => json!({
                                "tcb_svn": hex::encode(body.tcb_svn),
                                "mr_seam": hex::encode(body.mr_seam),
                                "mrsigner_seam": hex::encode(body.mrsigner_seam),
                                "seam_attributes": hex::encode(body.seam_attributes),
                                "td_attributes": hex::encode(body.td_attributes),
                                "xfam": hex::encode(body.xfam),
                                "mr_td": hex::encode(body.mr_td),
                                "mr_config_id": hex::encode(body.mr_config_id),
                                "mr_owner": hex::encode(body.mr_owner),
                                "mr_owner_config": hex::encode(body.mr_owner_config),
                                "rtmr_0": hex::encode(body.rtmr_0),
                                "rtmr_1": hex::encode(body.rtmr_1),
                                "rtmr_2": hex::encode(body.rtmr_2),
                                "rtmr_3": hex::encode(body.rtmr_3),
                                "report_data": hex::encode(body.report_data),
                            }),
                            QuoteV5Body::Tdx15(body) => json!({
                                "tcb_svn": hex::encode(body.tcb_svn),
                                "mr_seam": hex::encode(body.mr_seam),
                                "mrsigner_seam": hex::encode(body.mrsigner_seam),
                                "seam_attributes": hex::encode(body.seam_attributes),
                                "td_attributes": hex::encode(body.td_attributes),
                                "xfam": hex::encode(body.xfam),
                                "mr_td": hex::encode(body.mr_td),
                                "mr_config_id": hex::encode(body.mr_config_id),
                                "mr_owner": hex::encode(body.mr_owner),
                                "mr_owner_config": hex::encode(body.mr_owner_config),
                                "rtmr_0": hex::encode(body.rtmr_0),
                                "rtmr_1": hex::encode(body.rtmr_1),
                                "rtmr_2": hex::encode(body.rtmr_2),
                                "rtmr_3": hex::encode(body.rtmr_3),
                                "report_data": hex::encode(body.report_data),
                                "tee_tcb_svn2": hex::encode(body.tee_tcb_svn2),
                                "mr_servicetd": hex::encode(body.mr_servicetd),
                            }),
                        },
                        "type": match r#type {
                            QuoteV5Type::TDX10 => "0200",
                            QuoteV5Type::TDX15 => "0300",
                        },
                        "size": hex::encode(&size[..]),
                    },
                    "report_data": hex::encode(self.report_data()),
                    "init_data": hex::encode(self.mr_config_id()),
                    "td_attributes": td_attributes,
                })
            }
        };

        let mut claims = claims.as_object().expect("claims is not an object").clone();
        let platform_info =
            parse_platform_info(&self.cert_data().qe_certification_data.certificates)?;
        if let Some(piid) = platform_info.platform_instance_id {
            claims.insert(
                "platform_instance_id".to_string(),
                Value::String(hex::encode(&piid[..])),
            );
        }

        Ok(claims)
    }
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
        let supplemental_data = create_supp_data();

        let mut supp = deserialize_supp_data(&supplemental_data);

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

    fn create_supp_data() -> String {
        use std::mem::size_of;

        let root_key_id = hex::decode("46e403bd34f05a3f2817ab9badcaacc7ffc98e0f261008cd30dae936cace18d5dcf58eef31463613de1570d516200993")
            .expect("invalid root_key_id hex");

        let pck_ppid =
            hex::decode("27e0ea63c5bc76685225c63a3d844170").expect("invalid pck_ppid hex");

        let mut supp: sgx_ql_qv_supplemental_t = unsafe { std::mem::zeroed() };

        supp.earliest_issue_date = 1526899510;
        supp.latest_issue_date = 1756048752;
        supp.earliest_expiration_date = 1758639725;
        supp.tcb_level_date_tag = 1710288000;
        supp.tcb_eval_ref_num = 1;
        supp.pck_crl_num = 1;
        supp.root_ca_crl_num = 1;
        supp.sgx_type = 1; // Scalable
        supp.dynamic_platform = 1;
        supp.cached_keys = 1;
        supp.smt_enabled = 1;

        supp.root_key_id[..48].copy_from_slice(&root_key_id[..48]);
        supp.pck_ppid[..16].copy_from_slice(&pck_ppid[..16]);

        let bytes = unsafe {
            std::slice::from_raw_parts(
                &supp as *const _ as *const u8,
                size_of::<sgx_ql_qv_supplemental_t>(),
            )
        };

        STANDARD.encode(bytes)
    }
}
