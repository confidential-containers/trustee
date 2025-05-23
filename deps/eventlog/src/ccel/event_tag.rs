use super::{EventDataParser, EventDetails};
use anyhow::{anyhow, Result};
use scroll::{Pread, LE};

pub struct EvEventTagParser;

/// Parser for EV_EVENT_TAG
/// Define in section 10.2.6 of <https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf>
/// ```text
/// TCG_PCClientTaggedEvent {
///     UINT32 taggedEventID; // SKIPPED
///     UINT32 taggedEventDataSize;
///     BYTE taggedEventData[taggedEventDataSize];
/// }
/// ```
impl EventDataParser for EvEventTagParser {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails> {
        let mut index = size_of::<u32>();
        let data_size = data
            .gread_with::<u32>(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Cannot read length: {:?}", e))?;

        let event_data = data
            .get(index..index + data_size as usize)
            .ok_or_else(|| anyhow!("Failed to read description"))?;

        let event_desc = String::from_utf8(event_data.to_vec())?.replace('\0', "");
        Ok(EventDetails::from_string(event_desc))
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
    #[case::not_utf_part("", "Cannot read length: BadOffset(4)")]
    #[case::not_utf_part("0F", "Cannot read length: BadOffset(4)")]
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
