// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside a TDX Quote and CCEL and
//! serialize them into a JSON. The format will look like example available in test data:
//! ./test_data/parse_tdx_claims_expected.json

use anyhow::Result;
use bitflags::{bitflags, Flags};
use byteorder::{LittleEndian, ReadBytesExt};
use log::debug;
use serde_json::{Map, Value};
use thiserror::Error;

use super::quote::Quote;
use crate::{tdx::quote::QuoteV5Body, TeeEvidenceParsedClaim};
use eventlog::CcEventLog;

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

    let td_attributes = parse_td_attributes(quote.td_attributes())?;

    let mut claims = Map::new();

    // Claims from EventLog.
    if let Some(ccel) = cc_eventlog {
        let result = serde_json::to_value(ccel.clone().log)?;
        claims.insert("uefi_event_logs".to_string(), result);
    }

    parse_claim!(claims, "quote", quote_map);
    parse_claim!(claims, "td_attributes", td_attributes);

    parse_claim!(claims, "report_data", quote.report_data());
    parse_claim!(claims, "init_data", quote.mr_config_id());

    let claims_str = serde_json::to_string_pretty(&claims)?;
    debug!("Parsed Evidence claims map: \n{claims_str}\n");

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

bitflags! {
    #[derive(Debug, Clone)]
    struct TdAttributesFlags: u64 {
        const DEBUG            = 1 << 0;
        const SEPTVE_DISABLE   = 1 << 28;
        const PROTECTION_KEYS  = 1 << 30;
        const KEY_LOCKER       = 1 << 31;
        const PERFMON          = 1 << 63;
    }
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

#[derive(Error, Debug, PartialEq)]
pub enum PlatformConfigInfoError {
    #[error("Failed to parse `Descriptor`")]
    ParseDescriptor,

    #[error("Failed to parse `InfoLength`")]
    ReadInfoLength,

    #[error("invalid header")]
    InvalidHeader,

    #[error("not enough data after header")]
    NotEnoughData,
}

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
    type Error = PlatformConfigInfoError;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        let descriptor_size = core::mem::size_of::<Descriptor>();

        let info_size = core::mem::size_of::<InfoLength>();

        let header_size = descriptor_size + info_size;

        if data.len() < header_size {
            return Err(PlatformConfigInfoError::InvalidHeader);
        }

        let descriptor = data[0..descriptor_size]
            .try_into()
            .map_err(|_| PlatformConfigInfoError::ParseDescriptor)?;

        let info_length = (&data[descriptor_size..header_size])
            .read_u32::<LittleEndian>()
            .map_err(|_| PlatformConfigInfoError::ReadInfoLength)?;

        let total_size = header_size + info_length as usize;

        let data = data
            .get(header_size..total_size)
            .ok_or(PlatformConfigInfoError::NotEnoughData)?;

        std::result::Result::Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::Value;

    use crate::tdx::{claims::PlatformConfigInfoError, quote::parse_tdx_quote};

    use super::{generate_parsed_claim, TdShimPlatformConfigInfo};

    use eventlog::CcEventLog;
    use rstest::rstest;

    #[test]
    fn parse_tdx_claims() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let ccel_bin = std::fs::read("./test_data/CCEL_data").expect("read ccel failed");
        let quote = parse_tdx_quote(&quote_bin).expect("parse quote");
        let ccel = CcEventLog::try_from(ccel_bin).expect("parse ccel");
        let claims = generate_parsed_claim(quote, Some(ccel)).expect("parse claim failed");
        let expected_json_str =
            std::fs::read_to_string("./test_data/parse_tdx_claims_expected.json")
                .expect("read expected json output failed");
        let expected: Value =
            serde_json::from_str(&expected_json_str).expect("parsing expected json failed");

        assert_json_eq!(expected, claims);
    }

    #[rstest]
    #[trace]
    #[case(b"", Err(PlatformConfigInfoError::InvalidHeader))]
    #[case(b"0123456789ABCDEF", Err(PlatformConfigInfoError::InvalidHeader))]
    #[case(b"0123456789ABCDEF\x00", Err(PlatformConfigInfoError::InvalidHeader))]
    #[case(
        b"0123456789ABCDEF\x00\x00",
        Err(PlatformConfigInfoError::InvalidHeader)
    )]
    #[case(
        b"0123456789ABCDEF\x00\x00\x00",
        Err(PlatformConfigInfoError::InvalidHeader)
    )]
    #[case(b"0123456789ABCDEF\x00\x00\x00\x00", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 0, data: &[]}))]
    #[case(b"0123456789ABCDEF\x01\x00\x00\x00X", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 1, data: b"X"}))]
    #[case(b"0123456789ABCDEF\x03\x00\x00\x00ABC", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 3, data: b"ABC"}))]
    #[case(b"0123456789ABCDEF\x04\x00\x00\x00;):)", Ok(TdShimPlatformConfigInfo{descriptor: *b"0123456789ABCDEF", info_length: 4, data: b";):)"}))]
    #[case(
        b"0123456789ABCDEF\x01\x00\x00\x00",
        Err(PlatformConfigInfoError::NotEnoughData)
    )]
    fn test_td_shim_platform_config_info_try_from(
        #[case] data: &[u8],
        #[case] result: std::result::Result<TdShimPlatformConfigInfo, PlatformConfigInfoError>,
    ) {
        let actual_result = TdShimPlatformConfigInfo::try_from(data);
        assert_eq!(actual_result, result);
    }
}
