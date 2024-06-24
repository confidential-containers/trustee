// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside an SGX Quote and
//! serialize it into a JSON. A sample JSON looks like
//! ```json
//! {
//!     "header":{
//!         "version": "0300",
//!         "att_key_type": "0200",
//!         "att_key_data_0": "00000000",
//!         "qe_svn": "0800",
//!         "pce_svn": "0d00",
//!         "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
//!         "user_data": "dccde9b31ce8860548173bb4a2a57a1600000000"
//!     },
//!     "body":{
//!         "cpu_svn": "06060c0cffff00000000000000000000",
//!         "misc_select": "01000000",
//!         "reserved1": "000000000000000000000000",
//!         "isv_ext_prod_id": "00000000000000000000000000000000",
//!         "attributes.flags": "0700000000000000",
//!         "attributes.xfrm": "e700000000000000",
//!         "mr_enclave": "8f173e4613ff05c52aaf04162d234edae8c9977eae47eb2299ae16a553011c68",
//!         "reserved2": "0000000000000000000000000000000000000000000000000000000000000000",
//!         "mr_signer": "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e",
//!         "reserved3": "0000000000000000000000000000000000000000000000000000000000000000",
//!         "config_id": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!         "isv_prod_id": "0000",
//!         "isv_svn": "0000",
//!         "config_svn": "0000",
//!         "reserved4": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!         "isv_family_id": "00000000000000000000000000000000",
//!         "report_data": "74657374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
//!     }
//! }
//! ```

use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use serde_json::{Map, Value};

use crate::TeeEvidenceParsedClaim;

use super::types::*;

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

pub fn generate_parsed_claims(quote: sgx_quote3_t) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    // Claims from SGX Quote Header.
    parse_claim!(quote_header, "version", quote.header.version);
    parse_claim!(quote_header, "att_key_type", quote.header.att_key_type);
    parse_claim!(quote_header, "att_key_data_0", quote.header.att_key_data_0);
    parse_claim!(quote_header, "qe_svn", quote.header.qe_svn);
    parse_claim!(quote_header, "pce_svn", quote.header.pce_svn);
    parse_claim!(quote_header, "vendor_id", quote.header.vendor_id);
    parse_claim!(quote_header, "user_data", quote.header.user_data);

    parse_claim!(quote_body, "cpu_svn", quote.report_body.cpu_svn);
    parse_claim!(quote_body, "misc_select", quote.report_body.misc_select);
    parse_claim!(quote_body, "reserved1", quote.report_body.reserved1);
    parse_claim!(
        quote_body,
        "isv_ext_prod_id",
        quote.report_body.isv_ext_prod_id
    );
    parse_claim!(
        quote_body,
        "attributes.flags",
        quote.report_body.attributes.flags
    );
    parse_claim!(
        quote_body,
        "attributes.xfrm",
        quote.report_body.attributes.xfrm
    );
    parse_claim!(quote_body, "mr_enclave", quote.report_body.mr_enclave);
    parse_claim!(quote_body, "reserved2", quote.report_body.reserved2);
    parse_claim!(quote_body, "mr_signer", quote.report_body.mr_signer);
    parse_claim!(quote_body, "reserved3", quote.report_body.reserved3);
    parse_claim!(quote_body, "config_id", quote.report_body.config_id);
    parse_claim!(quote_body, "isv_prod_id", quote.report_body.isv_prod_id);
    parse_claim!(quote_body, "isv_svn", quote.report_body.isv_svn);
    parse_claim!(quote_body, "config_svn", quote.report_body.config_svn);
    parse_claim!(quote_body, "reserved4", quote.report_body.reserved4);
    parse_claim!(quote_body, "isv_family_id", quote.report_body.isv_family_id);
    parse_claim!(quote_body, "report_data", quote.report_body.report_data);

    let mut claims = Map::new();
    parse_claim!(claims, "header", quote_header);
    parse_claim!(claims, "body", quote_body);
    parse_claim!(claims, "report_data", quote.report_body.report_data);
    parse_claim!(claims, "init_data", quote.report_body.config_id);

    log::info!("\nParsed Evidence claims map: \n{:?}\n", &claims);

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

/// Kernel Commandline Event inside Eventlog
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: [u8; 16],
    pub info_length: u32,
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TdShimPlatformConfigInfo<'a> {
    type Error = anyhow::Error;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        if data.len() < core::mem::size_of::<[u8; 16]>() + core::mem::size_of::<u32>() {
            bail!("give data slice is too short");
        }

        let descriptor = data[0..core::mem::size_of::<[u8; 16]>()].try_into()?;
        let info_length = (&data[core::mem::size_of::<[u8; 16]>()
            ..core::mem::size_of::<[u8; 16]>() + core::mem::size_of::<u32>()])
            .read_u32::<LittleEndian>()?;
        let data = &data[core::mem::size_of::<[u8; 16]>() + core::mem::size_of::<u32>()
            ..core::mem::size_of::<[u8; 16]>()
                + core::mem::size_of::<u32>()
                + info_length as usize];
        Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::sgx::parse_sgx_quote;

    use super::generate_parsed_claims;

    #[test]
    fn parse_sgx_claims() {
        let quote_bin = include_bytes!("../../test_data/occlum_quote.dat");
        let quote = parse_sgx_quote(quote_bin.as_slice()).expect("parse quote");
        let claims = generate_parsed_claims(quote).expect("parse claim failed");
        let expected = json!({
            "header":{
                "version": "0300",
                "att_key_type": "0200",
                "att_key_data_0": "00000000",
                "qe_svn": "0800",
                "pce_svn": "0d00",
                "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                "user_data": "dccde9b31ce8860548173bb4a2a57a1600000000"
            },
            "body":{
                "cpu_svn": "06060c0cffff00000000000000000000",
                "misc_select": "01000000",
                "reserved1": "000000000000000000000000",
                "isv_ext_prod_id": "00000000000000000000000000000000",
                "attributes.flags": "0700000000000000",
                "attributes.xfrm": "e700000000000000",
                "mr_enclave": "8f173e4613ff05c52aaf04162d234edae8c9977eae47eb2299ae16a553011c68",
                "reserved2": "0000000000000000000000000000000000000000000000000000000000000000",
                "mr_signer": "83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e",
                "reserved3": "0000000000000000000000000000000000000000000000000000000000000000",
                "config_id": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "isv_prod_id": "0000",
                "isv_svn": "0000",
                "config_svn": "0000",
                "reserved4": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "isv_family_id": "00000000000000000000000000000000",
                "report_data": "74657374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            },
            "report_data": "74657374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "init_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });

        assert_json_eq!(expected, claims);
    }
}
