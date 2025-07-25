// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{EventDataParser, EventDetails};
use anyhow::{anyhow, Context, Result};
use scroll::{Pread, LE};
use serde::Serialize;
use serde_json::Value;

pub struct EvEventTagParser;

/// AAEL tagged event ID, ASCII of `"AAEL"`
const AAEL_TAGGED_EVENT_ID: u32 = 0x4141454c;

/// Parser for EV_EVENT_TAG
/// Defined in section 10.2.6 of <https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf>
/// ```text
/// TCG_PCClientTaggedEvent {
///     UINT32 taggedEventID;
///     UINT32 taggedEventDataSize;
///     BYTE taggedEventData[taggedEventDataSize];
/// }
/// ```
impl EventDataParser for EvEventTagParser {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails> {
        let mut index = 0;
        let event_id = data
            .gread_with::<u32>(&mut index, LE)
            .map_err(|e| anyhow!("Cannot read event id: {:?}", e))?;
        let data_size = data
            .gread_with::<u32>(&mut index, LE)
            .map_err(|e| anyhow!("Cannot read length: {:?}", e))?;

        let event_data = data
            .get(index..index + data_size as usize)
            .ok_or_else(|| anyhow!("Failed to read description"))?;

        let event_desc = String::from_utf8_lossy(event_data);
        let mut details = EventDetails::from_string(event_desc.replace('\0', "").to_string());

        if event_id == AAEL_TAGGED_EVENT_ID {
            let event_data =
                String::from_utf8(event_data.to_vec()).context("Illegal AAEL event data")?;
            let aael = AaelEventEntry::from_bytes(&event_data)?;
            details.data = Some(serde_json::to_value(aael)?);
            details.unicode_name = Some("AAEL".into());
        }

        Ok(details)
    }
}

#[derive(Serialize)]
pub struct AaelEventEntry {
    domain: String,
    operation: String,
    content: Value,
}

impl AaelEventEntry {
    pub fn from_bytes(s: &str) -> Result<Self> {
        let first_sp = s
            .find(' ')
            .ok_or(anyhow!("No space found in event string"))?;
        let after_first = &s[first_sp + 1..];
        let second_sp_rel = after_first
            .find(' ')
            .ok_or(anyhow!("No second space found in event string"))?;
        let second_sp = first_sp + 1 + second_sp_rel;

        let domain = s[..first_sp].to_string();
        let operation = s[first_sp + 1..second_sp].to_string();
        let content_str = &s[second_sp + 1..];
        let content = match serde_json::from_str(content_str) {
            Ok(content_json) => content_json,
            Err(_) => Value::String(content_str.to_string()),
        };
        Ok(Self {
            domain,
            operation,
            content,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        "ed223b8f1a0000004c4f414445445f494d4147453a3a4c6f61644f7074696f6e7300",
        EventDetails::from_string(String::from("LOADED_IMAGE::LoadOptions"))
    )]
    #[case(
        "ec223b8f0d0000004c696e757820696e6974726400",
        EventDetails::from_string(String::from("Linux initrd"))
    )]
    fn test_event_tag_parser(#[case] test_data: &str, #[case] expected_result: EventDetails) {
        let parser = EvEventTagParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_ok());
        assert_eq!(actual_result.unwrap(), expected_result);
    }

    #[rstest]
    #[case::not_utf_part("", "Cannot read event id: TooBig { size: 4, len: 0 }")]
    #[case::not_utf_part("0F", "Cannot read event id: TooBig { size: 4, len: 1 }")]
    #[case::not_utf_part(
        "0F74645f7061796c6f61640000109000000000000000001000000000",
        "Failed to read description"
    )]
    fn test_event_tag_parser_error(#[case] test_data: &str, #[case] expected_result: &str) {
        let parser = EvEventTagParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_err());
        assert_eq!(actual_result.unwrap_err().to_string(), expected_result);
    }
}
