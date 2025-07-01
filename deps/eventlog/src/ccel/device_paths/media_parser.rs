// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{DevicePathParser, DeviceSubTypeParser};
use crate::GUID_SIZE;
use anyhow::{anyhow, bail, Result};
use byteorder::{ByteOrder, LittleEndian};

/// Parser for Type 4 — Media Device Path.
/// Defined in section 10.3.5 of <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#media-device-path>
enum MediaSubType {
    HardDrive,
    MediaVendor,
    FilePath,
    // Add more subtype parsers here as needed
}

impl MediaSubType {
    fn from_u8(sub_type: u8) -> Result<Self> {
        match sub_type {
            0x01 => Ok(MediaSubType::HardDrive),
            0x03 => Ok(MediaSubType::MediaVendor),
            0x04 => Ok(MediaSubType::FilePath),
            _ => Err(anyhow!("Unknown Media subtype: {:#04x}", sub_type)),
        }
    }

    fn parse(&self, data: &[u8]) -> Result<String> {
        let parser: &dyn DeviceSubTypeParser = match self {
            MediaSubType::HardDrive => &HardDriveParser,
            MediaSubType::MediaVendor => &MediaVendorParser,
            MediaSubType::FilePath => &FilePathParser,
        };

        parser.parse(data)
    }
}

pub struct MediaParser;

impl DevicePathParser for MediaParser {
    fn parse(&self, sub_type: u8, data: &[u8]) -> Result<String> {
        MediaSubType::from_u8(sub_type).and_then(|path| path.parse(data))
    }
}

pub struct HardDriveParser;

impl DeviceSubTypeParser for HardDriveParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() < 37 {
            bail!("Hard drive data is too short");
        }
        let partition_number = u32::from_le_bytes(data[0..4].try_into()?);
        let partition_start_lba = u64::from_le_bytes(data[4..12].try_into()?);
        let partition_size_lba = u64::from_le_bytes(data[12..20].try_into()?);
        let partition_signature = &data[20..36];

        let partition_format = &data[36];
        let _signature_type = &data[37];

        let prefix;
        let sig;
        let mut partition_details = String::default();

        match partition_format {
            0x01 => {
                prefix = "MBR";
                sig = format!(
                    "{:#010x}",
                    u32::from_le_bytes(partition_signature[0..4].try_into()?)
                )
            }
            0x02 => {
                prefix = "GPT";
                sig = format_uefi_guid(partition_signature)
            }
            _ => {
                bail!("Unknown partition format {}", partition_format)
            }
        }

        if partition_number != 0 {
            partition_details = format!(",{:#x},{:#x}", partition_start_lba, partition_size_lba)
        }

        Ok(format!(
            "HD({},{},{}{})",
            partition_number, prefix, sig, partition_details
        ))
    }
}

pub struct MediaVendorParser;

impl DeviceSubTypeParser for MediaVendorParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() < GUID_SIZE {
            bail!("Vendor media data is too short");
        }
        let guid = &data[0..GUID_SIZE];
        let vendor_data = &data[GUID_SIZE..];

        Ok(format!(
            "VenMedia({},{})",
            format_uefi_guid(guid),
            hex::encode(vendor_data)
        ))
    }
}

pub struct FilePathParser;

impl DeviceSubTypeParser for FilePathParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.is_empty() || data.len() % 2 != 0 {
            bail!("File path is too short");
        }
        let utf16_words: Vec<u16> = data[0..data.len() - 2]
            .chunks_exact(2)
            .map(LittleEndian::read_u16)
            .collect();
        Ok(format!("File({})", String::from_utf16_lossy(&utf16_words)))
    }
}

pub fn format_uefi_guid(input: &[u8]) -> String {
    let data1 = u32::from_le_bytes([input[0], input[1], input[2], input[3]]);
    let data2 = u16::from_le_bytes([input[4], input[5]]);
    let data3 = u16::from_le_bytes([input[6], input[7]]);
    let data4 = &input[8..];

    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        data1,
        data2,
        data3,
        data4[0],
        data4[1],
        data4[2],
        data4[3],
        data4[4],
        data4[5],
        data4[6],
        data4[7]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(
        1,
        b"0f000000002800000000000000500300000000005e27f1007553d5439eb5de2add4c99320202",
        "HD(15,GPT,00F1275E-5375-43D5-9EB5-DE2ADD4C9932,0x2800,0x35000)"
    )]
    #[case(
        1,
        b"0100000000080000000000000000100000000000e9a896cbdcade74bb68e69b6d1ea59cb0202",
        "HD(1,GPT,CB96A8E9-ADDC-4BE7-B68E-69B6D1EA59CB,0x800,0x100000)"
    )]
    #[case(
        1,
        b"00000000000000000000000000000000000000000000000000000000431202a0000000000101",
        "HD(0,MBR,0x00000000)"
    )]
    #[case(
        1,
        b"01000000000800000000000000E02E0000000000431202a000000000431202a0000000000101",
        "HD(1,MBR,0xa0021243,0x800,0x2ee000)"
    )]
    #[case(
        1,
        b"0100000022000000000000000000710200000000009ae315d21d00108d7f00a0c92408fc0202",
        "HD(1,GPT,15E39A00-1DD2-1000-8D7F-00A0C92408FC,0x22,0x2710000)"
    )]
    #[case(
        3,
        b"f8d1c555cd04b5468a20e56cbb3052d0",
        "VenMedia(55C5D1F8-04CD-46B5-8A20-E56CBB3052D0,)"
    )]
    #[case(
        3,
        b"72f728144ab61e44b8c39ebdd7f893c7",
        "VenMedia(1428F772-B64A-441E-B8C3-9EBDD7F893C7,)"
    )]
    #[case(4, b"6b00650072006e0065006c000000", "File(kernel)")]
    #[case(
        4,
        b"5c004500460049005c0042004f004f0054005c0042004f004f0054005800360034002e004500460049000000",
        "File(\\EFI\\BOOT\\BOOTX64.EFI)"
    )]
    #[case(
        4,
        b"5c004500460049005c0042004f004f0054005c00660062007800360034002e006500660069000000",
        "File(\\EFI\\BOOT\\fbx64.efi)"
    )]
    #[case(4, b"5c004500460049005c007500620075006e00740075005c007300680069006d007800360034002e006500660069000000", "File(\\EFI\\ubuntu\\shimx64.efi)"
    )]
    #[case(4, b"5c004500460049005c007500620075006e00740075005c0067007200750062007800360034002e006500660069000000", "File(\\EFI\\ubuntu\\grubx64.efi)"
    )]
    fn test_formatter(#[case] sub_type: u8, #[case] data: &[u8], #[case] expected_result: &str) {
        let vendor_data = hex::decode(data).unwrap();
        let actual = MediaParser.parse(sub_type, &vendor_data);
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), expected_result);
    }

    #[rstest]
    #[case::cdrom(2, "Unknown Media subtype: 0x02")]
    #[case::media_protocol(5, "Unknown Media subtype: 0x05")]
    #[case::piwg_firmware_file(6, "Unknown Media subtype: 0x06")]
    #[case::piwg_firmware_volume(7, "Unknown Media subtype: 0x07")]
    #[case::relative_offset_range(8, "Unknown Media subtype: 0x08")]
    #[case::ram_disk(9, "Unknown Media subtype: 0x09")]
    fn unsupported_test(#[case] sub_type: u8, #[case] expected_msg: &str) {
        let actual = MediaParser.parse(sub_type, b"0000");
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err().to_string(), expected_msg);
    }
}
