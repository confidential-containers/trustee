use super::{DevicePathParser, DeviceSubTypeParser};
use anyhow::{anyhow, Result};
use scroll::{Pread, LE};
use std::str::from_utf8;

/// Parser for Type 5 - BIOS Boot Specification Device Path.
/// Define in section 10.3.6 of <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#bios-boot-specification-device-path>
enum BiosSubType {
    Bbs,
}

impl BiosSubType {
    fn from_u8(sub_type: u8) -> Result<Self> {
        match sub_type {
            0x01 => Ok(BiosSubType::Bbs),
            _ => Err(anyhow!(
                "Unknown Bios Boot Specification subtype: {:#04x}",
                sub_type
            )),
        }
    }

    fn parse(&self, data: &[u8]) -> Result<String> {
        let parser: &dyn DeviceSubTypeParser = match self {
            BiosSubType::Bbs => &BbsParser,
        };

        parser.parse(data)
    }
}

pub struct BiosBootSpecParser;

impl DevicePathParser for BiosBootSpecParser {
    fn parse(&self, sub_type: u8, data: &[u8]) -> Result<String> {
        BiosSubType::from_u8(sub_type).and_then(|path| path.parse(data))
    }
}

pub struct BbsParser;

impl DeviceSubTypeParser for BbsParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        let mut index = 0;

        let device_type = match data
            .gread_with::<u16>(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read device type: {:?}", e))?
        {
            0x01 => "FLOPPY",
            0x02 => "HARD_DRIVE",
            0x03 => "CDROM",
            0x04 => "PCMCIA",
            0x05 => "USB",
            0x06 => "EMBEDDED_NETWORK",
            0x80 => "DEV",
            0xFF => "UNKNOWN",
            other => &*other.to_string(),
        };

        let status_flag: u16 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read status flag: {:?}", e))?;

        let desc_bytes = &data[index..];

        let desc_end = desc_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(desc_bytes.len());

        let description = from_utf8(&desc_bytes[..desc_end])
            .map_err(|e| anyhow::anyhow!("Failed to parse description: {:?}", e))?;

        Ok(format!(
            "BBS({},{},{})",
            device_type, description, status_flag
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::bbs(1, b"0500000000", "BBS(USB,,0)")]
    #[case::bbs_allowed_type(1, b"F0FF000000", "BBS(65520,,0)")]
    #[case::bbs_with_desc(1, b"8000000041424300", "BBS(DEV,ABC,0)")]
    fn test_formatter(#[case] sub_type: u8, #[case] data: &[u8], #[case] expected_result: &str) {
        let vendor_data = hex::decode(data).unwrap();
        let actual = BiosBootSpecParser.parse(sub_type, &vendor_data);
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), expected_result);
    }
}
