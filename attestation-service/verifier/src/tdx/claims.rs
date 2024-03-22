// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside a TDX Quote and CCEL and
//! serialize them into a JSON. The format will look lile
//! ```json
//! {
//!  "ccel": {
//!    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
//!    "kernel_parameters": {
//!      "console": "hvc0",
//!      "root": "/dev/vda1",
//!      "rw": null
//!    }
//!  },
//!  "quote": {
//!    "header":{
//!        "version": "0400",
//!        "att_key_type": "0200",
//!        "tee_type": "81000000",
//!        "reserved": "00000000",
//!        "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
//!        "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
//!    },
//!    "body":{
//!        "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
//!        "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
//!        "seam_attributes": "0000000000000000",
//!        "td_attributes": "0100001000000000",
//!        "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
//!        "tcb_svn": "03000500000000000000000000000000",
//!        "xfam": "e742060000000000",
//!        "rtmr_0": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "rtmr_1": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "rtmr_2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!        "rtmr_3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//!    }
//!  }
//!}
//! ```

use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, warn};
use serde_json::{Map, Value};

use crate::{tdx::quote::QuoteV5Body, TeeEvidenceParsedClaim};

use super::{
    eventlog::{CcEventLog, MeasuredEntity},
    quote::Quote,
};

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        $map_name.insert($key_name.to_string(), serde_json::Value::Object($field))
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

pub fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_map = Map::new();
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    match &quote {
        Quote::V4 { header, body } => {
            parse_claim!(quote_header, "version", b"\x04\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
            parse_claim!(quote_body, "mr_seam", body.mr_seam);
            parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
            parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
            parse_claim!(quote_body, "td_attributes", body.td_attributes);
            parse_claim!(quote_body, "xfam", body.xfam);
            parse_claim!(quote_body, "mr_td", body.mr_td);
            parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
            parse_claim!(quote_body, "mr_owner", body.mr_owner);
            parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
            parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
            parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
            parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
            parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
            parse_claim!(quote_body, "report_data", body.report_data);

            parse_claim!(quote_map, "header", quote_header);
            parse_claim!(quote_map, "body", quote_body);
        }
        Quote::V5 {
            header,
            r#type,
            size,
            body,
        } => {
            parse_claim!(quote_header, "version", b"\x05\x00");
            parse_claim!(quote_header, "att_key_type", header.att_key_type);
            parse_claim!(quote_header, "tee_type", header.tee_type);
            parse_claim!(quote_header, "reserved", header.reserved);
            parse_claim!(quote_header, "vendor_id", header.vendor_id);
            parse_claim!(quote_header, "user_data", header.user_data);
            parse_claim!(quote_map, "type", r#type.as_bytes());
            parse_claim!(quote_map, "size", &size[..]);
            match body {
                QuoteV5Body::Tdx10(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
                QuoteV5Body::Tdx15(body) => {
                    parse_claim!(quote_body, "tcb_svn", body.tcb_svn);
                    parse_claim!(quote_body, "mr_seam", body.mr_seam);
                    parse_claim!(quote_body, "mrsigner_seam", body.mrsigner_seam);
                    parse_claim!(quote_body, "seam_attributes", body.seam_attributes);
                    parse_claim!(quote_body, "td_attributes", body.td_attributes);
                    parse_claim!(quote_body, "xfam", body.xfam);
                    parse_claim!(quote_body, "mr_td", body.mr_td);
                    parse_claim!(quote_body, "mr_config_id", body.mr_config_id);
                    parse_claim!(quote_body, "mr_owner", body.mr_owner);
                    parse_claim!(quote_body, "mr_owner_config", body.mr_owner_config);
                    parse_claim!(quote_body, "rtmr_0", body.rtmr_0);
                    parse_claim!(quote_body, "rtmr_1", body.rtmr_1);
                    parse_claim!(quote_body, "rtmr_2", body.rtmr_2);
                    parse_claim!(quote_body, "rtmr_3", body.rtmr_3);
                    parse_claim!(quote_body, "report_data", body.report_data);

                    parse_claim!(quote_body, "tee_tcb_svn2", body.tee_tcb_svn2);
                    parse_claim!(quote_body, "mr_servicetd", body.mr_servicetd);
                    parse_claim!(quote_map, "header", quote_header);
                    parse_claim!(quote_map, "body", quote_body);
                }
            }
        }
    }

    // Claims from CC EventLog.
    let mut ccel_map = Map::new();
    if let Some(ccel) = cc_eventlog {
        parse_ccel(ccel, &mut ccel_map)?;
    } else {
        warn!("parse CC EventLog: CCEL is null");
    }

    let mut claims = Map::new();
    parse_claim!(claims, "quote", quote_map);
    parse_claim!(claims, "ccel", ccel_map);

    parse_claim!(claims, "report_data", quote.report_data());
    parse_claim!(claims, "init_data", quote.mr_config_id());

    log::info!("\nParsed Evidence claims map: \n{:?}\n", &claims);

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

fn parse_ccel(ccel: CcEventLog, ccel_map: &mut Map<String, Value>) -> Result<()> {
    // Digest of kernel using td-shim
    match ccel.query_digest(MeasuredEntity::TdShimKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No td-shim kernel hash in CCEL");
        }
    }

    // Digest of kernel using TDVF
    match ccel.query_digest(MeasuredEntity::TdvfKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No tdvf kernel hash in CCEL");
        }
    }

    // Map of Kernel Parameters
    match ccel.query_event_data(MeasuredEntity::TdShimKernelParams) {
        Some(config_info) => {
            let td_shim_platform_config_info =
                TdShimPlatformConfigInfo::try_from(&config_info[..])?;

            let parameters = parse_kernel_parameters(td_shim_platform_config_info.data)?;
            ccel_map.insert(
                "kernel_parameters".to_string(),
                serde_json::Value::Object(parameters),
            );
        }
        _ => {
            warn!("No kernel parameters in CCEL");
        }
    }

    Ok(())
}

const ERR_INVALID_HEADER: &str = "invalid header";
const ERR_NOT_ENOUGH_DATA: &str = "not enough data after header";

type Descriptor = [u8; 16];
type InfoLength = u32;

/// Kernel Commandline Event inside Eventlog
#[derive(Debug, PartialEq)]
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: Descriptor,
    pub info_length: InfoLength,
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TdShimPlatformConfigInfo<'a> {
    type Error = anyhow::Error;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        let descriptor_size = core::mem::size_of::<Descriptor>();

        let info_size = core::mem::size_of::<InfoLength>();

        let header_size = descriptor_size + info_size;

        if data.len() < header_size {
            bail!(ERR_INVALID_HEADER);
        }

        let descriptor = data[0..descriptor_size].try_into()?;

        let info_length = (&data[descriptor_size..header_size]).read_u32::<LittleEndian>()?;

        let total_size = header_size + info_length as usize;

        let data = data
            .get(header_size..total_size)
            .ok_or(ERR_NOT_ENOUGH_DATA)
            .map_err(|e| anyhow!(e))?;

        Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

fn parse_kernel_parameters(kernel_parameters: &[u8]) -> Result<Map<String, Value>> {
    let parameters_str = String::from_utf8(kernel_parameters.to_vec())?;
    debug!("kernel parameters: {parameters_str}");

    let parameters = parameters_str
        .split(&[' ', '\n', '\r', '\0'])
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|item| {
            if item.is_empty() {
                return None;
            }

            let it = item.split_once('=');

            match it {
                Some((k, v)) => Some((k.into(), v.into())),
                None => Some((item.to_string(), Value::Null)),
            }
        })
        .collect();

    Ok(parameters)
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use assert_json_diff::assert_json_eq;
    use serde_json::{json, to_value, Map, Value};

    use crate::tdx::{eventlog::CcEventLog, quote::parse_tdx_quote};

    use super::{
        generate_parsed_claim, parse_kernel_parameters, TdShimPlatformConfigInfo,
        ERR_INVALID_HEADER, ERR_NOT_ENOUGH_DATA,
    };

    use rstest::rstest;

    // This is used with anyhow!() to create an actual error. However, we
    // don't care about the type of error: it's simply used to denote that
    // some sort of Err() occurred.
    const SOME_ERROR: &str = "an error of some sort occurred";

    #[test]
    fn parse_tdx_claims() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let ccel_bin = std::fs::read("./test_data/CCEL_data").expect("read ccel failed");
        let quote = parse_tdx_quote(&quote_bin).expect("parse quote");
        let ccel = CcEventLog::try_from(ccel_bin).expect("parse ccel");
        let claims = generate_parsed_claim(quote, Some(ccel)).expect("parse claim failed");
        let expected = json!({
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
                    "xfam": "e742060000000000",
                    "rtmr_0": "e940da7c2712d2790e2961e00484f4fa8e6f9eed71361655ae22699476b14f9e63867eb41edd4b480fef0c59f496b288",
                    "rtmr_1": "559cfcf42716ed6c40a48a73d5acb7da255435012f0a9f00fbe8c1c57612ede486a5684c4c9ff3ddf52315fcdca3a596",
                    "rtmr_2": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "rtmr_3": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                }
            },
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429"
        });

        assert_json_eq!(expected, claims);
    }

    #[rstest]
    #[trace]
    #[case(b"", Ok(Map::from_iter(vec![].into_iter())))]
    // Invalid UTF8 data
    #[case(b"\xff\xff", Err(anyhow!(SOME_ERROR)))]
    // Invalid UTF8 data
    #[case(b"foo=\xff\xff", Err(anyhow!(SOME_ERROR)))]
    #[case(b"name_only", Ok(Map::from_iter(vec![
                ("name_only".to_string(), Value::Null)
    ].into_iter())))]
    #[case(b"a=b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap())
    ].into_iter())))]
    #[case(b"\ra=b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap())
    ].into_iter())))]
    #[case(b"\na=b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap())
    ].into_iter())))]
    #[case(b"a=b\nc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\n\nc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\rc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\r\rc=d", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap())
    ].into_iter())))]
    #[case(b"a=b\rc=d\ne=foo", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap()),
                ("e".to_string(), to_value("foo").unwrap())
    ].into_iter())))]
    #[case(b"a=b\rc=d\nname_only\0e=foo", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("d").unwrap()),
                ("name_only".to_string(), Value::Null),
                ("e".to_string(), to_value("foo").unwrap())
    ].into_iter())))]
    #[case(b"foo='bar'", Ok(Map::from_iter(vec![
                ("foo".to_string(), to_value("'bar'").unwrap())
    ].into_iter())))]
    #[case(b"foo=\"bar\"", Ok(Map::from_iter(vec![
                ("foo".to_string(), to_value("\"bar\"").unwrap())
    ].into_iter())))]
    // Spaces in parameter values are not supported.
    // XXX: Note carefully the apostrophe values below!
    #[case(b"params_with_spaces_do_not_work='a b c'", Ok(Map::from_iter(vec![
                ("b".to_string(), Value::Null),
                ("c'".to_string(), Value::Null),
                ("params_with_spaces_do_not_work".to_string(), to_value("'a").unwrap()),
    ].into_iter())))]
    #[case(b"params_with_spaces_do_not_work=\"a b c\"", Ok(Map::from_iter(vec![
                ("b".to_string(), Value::Null),
                ("c\"".to_string(), Value::Null),
                ("params_with_spaces_do_not_work".to_string(), to_value("\"a").unwrap()),
    ].into_iter())))]
    #[case(b"a==", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=").unwrap())
    ].into_iter())))]
    #[case(b"a==b", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=b").unwrap())
    ].into_iter())))]
    #[case(b"a==b=", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=b=").unwrap())
    ].into_iter())))]
    #[case(b"a=b=c", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b=c").unwrap())
    ].into_iter())))]
    #[case(b"a==b==c", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("=b==c").unwrap())
    ].into_iter())))]
    #[case(b"module_foo=bar=baz,wibble_setting=2", Ok(Map::from_iter(vec![
                ("module_foo".to_string(), to_value("bar=baz,wibble_setting=2").unwrap())
    ].into_iter())))]
    #[case(b"a=b c== d=e", Ok(Map::from_iter(vec![
                ("a".to_string(), to_value("b").unwrap()),
                ("c".to_string(), to_value("=").unwrap()),
                ("d".to_string(), to_value("e").unwrap()),
    ].into_iter())))]
    fn test_parse_kernel_parameters(
        #[case] params: &[u8],
        #[case] result: Result<Map<String, Value>>,
    ) {
        let msg = format!(
            "test: params: {:?}, result: {result:?}",
            String::from_utf8_lossy(&params.to_vec())
        );

        let actual_result = parse_kernel_parameters(params);

        let msg = format!("{msg}: actual result: {actual_result:?}");

        if std::env::var("DEBUG").is_ok() {
            println!("DEBUG: {msg}");
        }

        if result.is_err() {
            assert!(actual_result.is_err(), "{msg}");
            return;
        }

        let expected_result_str = format!("{result:?}");
        let actual_result_str = format!("{actual_result:?}");

        assert_eq!(expected_result_str, actual_result_str, "{msg}");

        let result = result.unwrap();
        let actual_result = actual_result.unwrap();

        let expected_count = result.len();

        let actual_count = actual_result.len();

        let msg = format!("{msg}: expected_count: {expected_count}, actual_count: {actual_count}");

        assert_eq!(expected_count, actual_count, "{msg}");

        for expected_kv in &result {
            let key = expected_kv.0.to_string();
            let value = expected_kv.1.to_string();

            let value_found = actual_result.get(&key);

            let kv_msg = format!("{msg}: key: {key:?}, value: {value:?}");

            if std::env::var("DEBUG").is_ok() {
                println!("DEBUG: {kv_msg}");
            }

            assert!(value_found.is_some(), "{kv_msg}");

            let value_found = value_found.unwrap().to_string();

            assert_eq!(value_found, value, "{kv_msg}");
        }
    }

    #[rstest]
    #[trace]
    #[case(b"", Err(anyhow!(ERR_INVALID_HEADER)))]
    #[case(b"0123456789ABCDEF", Err(anyhow!(ERR_INVALID_HEADER)))]
    #[case(b"0123456789ABCDEF\x00", Err(anyhow!(ERR_INVALID_HEADER)))]
    #[case(b"0123456789ABCDEF\x00\x00", Err(anyhow!(ERR_INVALID_HEADER)))]
    #[case(b"0123456789ABCDEF\x00\x00\x00", Err(anyhow!(ERR_INVALID_HEADER)))]
    #[case(b"0123456789ABCDEF\x00\x00\x00\x00", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 0, data: &[]}))]
    #[case(b"0123456789ABCDEF\x01\x00\x00\x00X", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 1, data: b"X"}))]
    #[case(b"0123456789ABCDEF\x03\x00\x00\x00ABC", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 3, data: b"ABC"}))]
    #[case(b"0123456789ABCDEF\x04\x00\x00\x00;):)", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 4, data: b";):)"}))]
    #[case(b"0123456789ABCDEF\x01\x00\x00\x00", Err(anyhow!(ERR_NOT_ENOUGH_DATA)))]
    fn test_td_shim_platform_config_info_try_from(
        #[case] data: &[u8],
        #[case] result: Result<TdShimPlatformConfigInfo>,
    ) {
        let msg = format!(
            "test: data: {:?}, result: {result:?}",
            String::from_utf8_lossy(&data.to_vec())
        );

        let actual_result = TdShimPlatformConfigInfo::try_from(data);

        let msg = format!("{msg}: actual result: {actual_result:?}");

        if std::env::var("DEBUG").is_ok() {
            println!("DEBUG: {msg}");
        }

        if result.is_err() {
            let expected_result_str = format!("{result:?}");
            let actual_result_str = format!("{actual_result:?}");

            assert_eq!(expected_result_str, actual_result_str, "{msg}");
            return;
        }

        let actual_result = actual_result.unwrap();
        let expected_result = result.unwrap();

        assert_eq!(expected_result, actual_result, "{msg}");
    }
}
