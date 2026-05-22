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
use serde_json::{Map, Value};

use crate::intel_dcap::pck::PlatformInfo;
use crate::intel_dcap::quote::Quote;
use crate::TeeEvidenceParsedClaim;

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

pub fn generate_parsed_claims(
    quote: &Quote,
    platform_info: &PlatformInfo,
) -> Result<TeeEvidenceParsedClaim> {
    let Quote::V3 { header, body, .. } = quote else {
        bail!("expected SGX v3 quote");
    };
    let mut quote_body = Map::new();
    let mut quote_header = Map::new();

    // Claims from SGX Quote Header.
    // tee_type encodes the same bytes as att_key_data_0 in the SGX v3 wire format.
    // reserved[0..2] and reserved[2..4] encode qe_svn and pce_svn respectively.
    parse_claim!(quote_header, "version", header.version);
    parse_claim!(quote_header, "att_key_type", header.att_key_type);
    parse_claim!(quote_header, "att_key_data_0", header.tee_type);
    parse_claim!(quote_header, "qe_svn", &header.reserved[..2]);
    parse_claim!(quote_header, "pce_svn", &header.reserved[2..]);
    parse_claim!(quote_header, "vendor_id", header.vendor_id);
    parse_claim!(quote_header, "user_data", header.user_data);

    parse_claim!(quote_body, "cpu_svn", body.cpu_svn);
    parse_claim!(quote_body, "misc_select", body.misc_select);
    parse_claim!(quote_body, "reserved1", body.reserved1);
    parse_claim!(quote_body, "isv_ext_prod_id", body.isv_ext_prod_id);
    parse_claim!(quote_body, "attributes.flags", body.attributes_flags);
    parse_claim!(quote_body, "attributes.xfrm", body.attributes_xfrm);
    parse_claim!(quote_body, "mr_enclave", body.mr_enclave);
    parse_claim!(quote_body, "reserved2", body.reserved2);
    parse_claim!(quote_body, "mr_signer", body.mr_signer);
    parse_claim!(quote_body, "reserved3", body.reserved3);
    parse_claim!(quote_body, "config_id", body.config_id);
    parse_claim!(quote_body, "isv_prod_id", body.isv_prod_id);
    parse_claim!(quote_body, "isv_svn", body.isv_svn);
    parse_claim!(quote_body, "config_svn", body.config_svn);
    parse_claim!(quote_body, "reserved4", body.reserved4);
    parse_claim!(quote_body, "isv_family_id", body.isv_family_id);
    parse_claim!(quote_body, "report_data", body.report_data);

    let mut claims = Map::new();
    parse_claim!(claims, "header", quote_header);
    parse_claim!(claims, "body", quote_body);
    parse_claim!(claims, "report_data", body.report_data);
    parse_claim!(claims, "init_data", body.config_id);

    if let Some(piid) = platform_info.platform_instance_id {
        parse_claim!(claims, "platform_instance_id", &piid[..]);
    }

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use super::generate_parsed_claims;
    use crate::intel_dcap::pck::parse_platform_info;

    #[test]
    fn parse_sgx_claims() {
        let quote_bin = include_bytes!("../../test_data/occlum_quote.dat");
        let quote =
            crate::intel_dcap::quote::parse_quote(quote_bin.as_slice()).expect("parse quote");
        let platform_info =
            parse_platform_info(&quote.cert_data().qe_certification_data.certificates)
                .expect("parse platform info");
        let claims = generate_parsed_claims(&quote, &platform_info).expect("parse claim failed");
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
            "init_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "platform_instance_id": "7a3a6941065cd5060bd93d3db2cfc0c8"
        });

        assert_json_eq!(expected, claims);
    }
}
