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
//!     },
//!     "report_data": "74657374000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!     "init_data": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!     "platform_instance_id": "7a3a6941065cd5060bd93d3db2cfc0c8"
//! }
//! ```

use anyhow::Result;
use serde_json::Value;

use crate::intel_dcap::quote::Quote;
use crate::TeeEvidenceParsedClaim;

pub fn generate_parsed_claims(quote: &Quote) -> Result<TeeEvidenceParsedClaim> {
    let claims = quote.generate_parsed_claim()?;

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use super::generate_parsed_claims;

    #[test]
    fn parse_sgx_claims() {
        let quote_bin = include_bytes!("../../test_data/occlum_quote.dat");
        let quote =
            crate::intel_dcap::quote::parse_quote(quote_bin.as_slice()).expect("parse quote");
        let claims = generate_parsed_claims(&quote).expect("parse claim failed");
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
