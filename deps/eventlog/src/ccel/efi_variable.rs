// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{EventDataParser, EventDetails};
use crate::GUID_SIZE;
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use byteorder::{ByteOrder, LittleEndian};
use scroll::{Pread, LE};

pub struct EvEfiVariableParser;

/// Parser for EV_EFI_VARIABLE_AUTHORITY, EV_EFI_VARIABLE_BOOT2, EV_EFI_VARIABLE_BOOT, EV_EFI_VARIABLE_DRIVER_CONFIG
/// Defined in section 10.4.2 of <https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf>
/// All defined above structures share below structure:
/// ```text
/// UEFI_VARIABLE_DATA {
///     UEFI_GUID VariableName;
///     UINT64 UnicodeNameLength;
///     UINT64 VariableDataLength;
///     CHAR16 UnicodeName[];
///     INT8 VariableData[];
/// }
/// ```
impl EventDataParser for EvEfiVariableParser {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails> {
        let mut index = 0;

        let guid = data
            .get(index..index + GUID_SIZE)
            .ok_or_else(|| anyhow!("Failed to read GUID"))?;
        index += GUID_SIZE;

        let uname_length: u64 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read unicode name length: {:?}", e))?;

        let var_data_length: u64 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read variable data length: {:?}", e))?;

        let desc_byte_len = uname_length
            .checked_mul(2)
            .ok_or_else(|| anyhow!("Out of bounds while reading description length"))?
            as usize;

        let description_bytes = data
            .get(index..index + desc_byte_len)
            .ok_or_else(|| anyhow!("Out of bounds while reading description bytes"))?;

        index += desc_byte_len;

        let utf16_words: Vec<u16> = description_bytes
            .chunks_exact(2)
            .map(LittleEndian::read_u16)
            .collect();

        let unicode_name = String::from_utf16(&utf16_words)?;

        let variable_data = if var_data_length > 0 {
            let data_len = var_data_length as usize;
            let bytes = data
                .get(index..index + data_len)
                .ok_or_else(|| anyhow!("Out of bounds while reading variable_data"))?;
            STANDARD.encode(bytes)
        } else {
            String::new()
        };

        Ok(EventDetails {
            string: None,
            unicode_name: Some(unicode_name),
            unicode_name_length: Some(uname_length),
            variable_data: Some(variable_data),
            variable_data_length: Some(var_data_length),
            variable_name: Some(format_guid(guid)),
            device_paths: None,
            data: None,
        })
    }
}

fn format_guid(guid: &[u8]) -> String {
    format!(
        "{}-{}-{}-{}-{}",
        hex::encode(&guid[0..4]),
        hex::encode(&guid[4..6]),
        hex::encode(&guid[6..8]),
        hex::encode(&guid[8..10]),
        hex::encode(&guid[10..16])
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::ev_efi_variable_driver_config("61dfe48bca93d211aa0d00e098032b8c0a00000000000000000000000000000053006500630075007200650042006f006f007400",
    EventDetails { string: None, unicode_name: Some("SecureBoot".to_string()), unicode_name_length: Some(10), variable_data: Some("".to_string()), variable_data_length: Some(0), variable_name: Some("61dfe48b-ca93-d211-aa0d-00e098032b8c".to_string()), device_paths: None, data: None }
    )]
    #[case::ev_efi_variable_driver_config("61dfe48bca93d211aa0d00e098032b8c0200000000000000000000000000000050004b00",
    EventDetails { string: None, unicode_name: Some("PK".to_string()), unicode_name_length: Some(2), variable_data: Some("".to_string()), variable_data_length: Some(0), variable_name: Some("61dfe48b-ca93-d211-aa0d-00e098032b8c".to_string()), device_paths: None, data: None }
    )]
    #[case::ev_efi_variable_boot("61dfe48bca93d211aa0d00e098032b8c0900000000000000020000000000000042006f006f0074004f0072006400650072000000",
    EventDetails { string: None, unicode_name: Some("BootOrder".to_string()), unicode_name_length: Some(9), variable_data: Some("AAA=".to_string()), variable_data_length: Some(2), variable_name: Some("61dfe48b-ca93-d211-aa0d-00e098032b8c".to_string()), device_paths: None, data: None }
    )]
    #[case::ev_efi_variable_authority("50ab5d6046e00043abb63dd810dd8b2309000000000000002e0000000000000053006200610074004c006500760065006c00736261742c312c323032333031323930300a7368696d2c320a677275622c330a677275622e64656269616e2c340a",
    EventDetails { string: None, unicode_name: Some("SbatLevel".to_string()), unicode_name_length: Some(9), variable_data: Some("c2JhdCwxLDIwMjMwMTI5MDAKc2hpbSwyCmdydWIsMwpncnViLmRlYmlhbiw0Cg==".to_string()), variable_data_length: Some(46), variable_name: Some("50ab5d60-46e0-0043-abb6-3dd810dd8b23".to_string()), device_paths: None, data: None }
    )]
    fn test_efi_variable_parser(#[case] test_data: &str, #[case] expected_result: EventDetails) {
        let parser = EvEfiVariableParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_ok());
        assert_eq!(actual_result.unwrap(), expected_result);
    }

    #[rstest]
    #[case::not_utf_part("", "Failed to read GUID")]
    #[case(
        "61dfe48bca93d211aa0d00e098032b8c",
        "Failed to read unicode name length: TooBig { size: 8, len: 0 }"
    )]
    #[case(
        "61dfe48bca93d211aa0d00e098032b8c0a00000000000000",
        "Failed to read variable data length: TooBig { size: 8, len: 0 }"
    )]
    #[case(
        "61dfe48bca93d211aa0d00e098032b8c0a000000000000000000000000000000",
        "Out of bounds while reading description bytes"
    )]
    fn test_ipl_parser_error(#[case] test_data: &str, #[case] expected_result: &str) {
        let parser = EvEfiVariableParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_err());
        assert_eq!(actual_result.unwrap_err().to_string(), expected_result);
    }
}
