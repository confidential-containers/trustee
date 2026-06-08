// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside a TDX Quote and CCEL and
//! serialize them into a JSON. The format will look like example available in test data:
//! ./test_data/parse_tdx_claims_expected.json

use anyhow::Result;

use serde_json::Value;

use crate::{intel_dcap::quote::Quote, TeeEvidenceParsedClaim};

use eventlog::CcEventLog;

pub fn generate_parsed_claim(
    quote: &Quote,
    cc_eventlog: Option<CcEventLog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut claims = quote.generate_parsed_claim()?;

    // Claims from EventLog.
    if let Some(ccel) = cc_eventlog {
        let result = serde_json::to_value(ccel.clone().log)?;
        claims.insert("uefi_event_logs".to_string(), result);
    }

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

#[cfg(test)]
use thiserror::Error;

#[cfg(test)]
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

#[cfg(test)]
type Descriptor = [u8; 16];
#[cfg(test)]
type InfoLength = u32;

/// Kernel Commandline Event inside Eventlog
#[cfg(test)]
#[derive(Debug, PartialEq)]
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: Descriptor,
    pub info_length: InfoLength,
    pub data: &'a [u8],
}

#[cfg(test)]
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

        let info_bytes: [u8; 4] = data[descriptor_size..header_size]
            .try_into()
            .map_err(|_| PlatformConfigInfoError::ReadInfoLength)?;

        let info_length = u32::from_le_bytes(info_bytes);

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

    use crate::intel_dcap::quote::parse_quote;
    use crate::tdx::claims::PlatformConfigInfoError;

    use super::{generate_parsed_claim, TdShimPlatformConfigInfo};

    use eventlog::CcEventLog;
    use rstest::rstest;

    #[test]
    fn parse_tdx_claims() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let ccel_bin = std::fs::read("./test_data/CCEL_data").expect("read ccel failed");
        let quote = parse_quote(&quote_bin).expect("parse quote");
        let ccel = CcEventLog::try_from(ccel_bin).expect("parse ccel");
        let claims = generate_parsed_claim(&quote, Some(ccel)).expect("parse claim failed");
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
