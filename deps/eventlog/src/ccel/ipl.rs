// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{EventDataParser, EventDetails};
use anyhow::{bail, Result};
use byteorder::{ByteOrder, LittleEndian};

pub struct EvIplParser;

const GCE_IPL_PREFIX: [u8; 2] = [0x2e, 0x00];

/// Parser for EV_IPL event
/// This event is vendor defined.
/// For Google Cloud it's prefixed with 2e00
/// Defined in section 10.4.1 of <https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf>
impl EventDataParser for EvIplParser {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails> {
        if data.len() < 2 {
            bail!("Data is too short: expected at least 2 bytes");
        }
        let event_desc: String = if GCE_IPL_PREFIX == data[0..2] {
            let prefix_len = GCE_IPL_PREFIX.len();
            let len_minus_stop = data.len() - prefix_len;

            if len_minus_stop == 0 || len_minus_stop % 2 != 0 {
                bail!("Data is too short or not UTF-16 string");
            }

            let utf16_words: Vec<u16> = data[prefix_len..len_minus_stop]
                .chunks_exact(2)
                .map(LittleEndian::read_u16)
                .collect();
            String::from_utf16_lossy(&utf16_words)
        } else {
            String::from_utf8(data.to_vec())?.replace('\0', "")
        };
        Ok(EventDetails::from_string(event_desc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("4d6f", EventDetails::from_string(String::from("Mo")))]
    #[case("4d6f6b", EventDetails::from_string(String::from("Mok")))]
    #[case("4d6f6b4c69737400", EventDetails::from_string(String::from("MokList")))]
    #[case(
        "4d6f6b4c6973745800",
        EventDetails::from_string(String::from("MokListX"))
    )]
    #[case(
        "4d6f6b4c6973745472757374656400",
        EventDetails::from_string(String::from("MokListTrusted"))
    )]
    #[case::gcloud(
        "2e006c0069006e00750078000000",
        EventDetails::from_string(String::from("linux"))
    )]
    #[case::gcloud(
        "2e0063006d0064006c0069006e0065000000",
        EventDetails::from_string(String::from("cmdline"))
    )]
    #[case::gcloud(
        "2e0073006200610074000000",
        EventDetails::from_string(String::from("sbat"))
    )]
    #[case::alibabacloud(
        "677275625f636d64207365742070616765723d310000",
        EventDetails::from_string(String::from("grub_cmd set pager=1"))
    )]
    fn test_ipl_parser(#[case] test_data: &str, #[case] expected_result: EventDetails) {
        let parser = EvIplParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_ok());
        assert_eq!(actual_result.unwrap(), expected_result);
    }

    #[rstest]
    #[case::not_utf_part("", "Data is too short: expected at least 2 bytes")]
    #[case::gcloud("2e00", "Data is too short or not UTF-16 string")]
    #[case::gcloud("2e0000", "Data is too short or not UTF-16 string")]
    fn test_ipl_parser_error(#[case] test_data: &str, #[case] expected_result: &str) {
        let parser = EvIplParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_err());
        assert_eq!(actual_result.unwrap_err().to_string(), expected_result);
    }
}
