use super::{EventDataParser, EventDetails};
use anyhow::{bail, Result};
pub struct SimpleStringParser;

/// Parser for EV_EFI_HANDOFF_TABLES2 & EV_EFI_PLATFORM_FIRMWARE_BLOB2
/// Define in section 10.2.5 of <https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf>
/// ```text
/// UEFI_PLATFORM_FIRMWARE_BLOB2 {
///     UINT8 BlobDescriptionSize; // PARSED
///     BYTE[BlobDescriptionSize] BlobDescription; // PARSED
///     UEFI_PHYSICAL_ADDRESS BlobBase;
///     UINT64 BlobLength;
/// }
/// ```
/// ```text
/// EV_EFI_HANDOFF_TABLES2 contains UEFI_HANDOFF_TABLE_POINTERS2 {
///     UINT8 TableDescriptionSize; // PARSED
///     BYTE[TableDescriptionSize] TableDescription; // PARSED
///     UINT64 NumberOfTables;
///     UEFI_CONFIGURATION_TABLE TableEntry[NumberOfTables];
/// }
/// ```
impl EventDataParser for SimpleStringParser {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails> {
        if data.is_empty() {
            bail!("Data is too short: expected at least 1 byte");
        }

        let length = data[0] as usize;
        let start = 1;
        let end = start + length - start;

        if data.len() < end {
            bail!("Data is too short: expected at least {} bytes", end);
        }

        let description_bytes = &data[start..end];
        let event_desc = String::from_utf8(description_bytes.to_vec())?;
        Ok(EventDetails::from_string(event_desc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::ev_efi_handoff_tables2(
        "095464785461626c65000100000000000000af96bb93f2b9b84e9462e0ba745642360090800000000000",
        EventDetails::from_string(String::from("TdxTable"))
    )]
    #[case::ev_efi_handoff_tables2(
        "0b74645f7061796c6f61640000109000000000000000001000000000",
        EventDetails::from_string(String::from("td_payload"))
    )]
    #[case::ev_efi_platform_firmware_blob2("2946762858585858585858582d585858582d585858582d585858582d58585858585858585858585829000000c0ff000000000040080000000000", EventDetails::from_string(String::from("Fv(XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX)")))]
    #[case::ev_efi_platform_firmware_blob2("2946762834384442354531372d373037432d343732442d393143442d31363133453745463531423029000000e0ff000000000000020000000000", EventDetails::from_string(String::from("Fv(48DB5E17-707C-472D-91CD-1613E7EF51B0)")))]
    fn test_simple_string_parser(#[case] test_data: &str, #[case] expected_result: EventDetails) {
        let parser = SimpleStringParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_ok());
        assert_eq!(actual_result.unwrap(), expected_result);
    }

    #[rstest]
    #[case::too_short("", "Data is too short: expected at least 1 byte")]
    #[case::too_short("0F", "Data is too short: expected at least 15 bytes")]
    #[case::invalid_len(
        "0F74645f7061796c6f61640000109000000000000000001000000000",
        "invalid utf-8 sequence of 1 bytes from index 13"
    )]
    #[case::invalid_len(
        "3774645f7061796c6f61640000109000000000000000001000000000",
        "Data is too short: expected at least 55 bytes"
    )]
    fn test_simple_string_parser_error(#[case] test_data: &str, #[case] expected_result: &str) {
        let parser = SimpleStringParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_err());
        assert_eq!(actual_result.unwrap_err().to_string(), expected_result);
    }
}
