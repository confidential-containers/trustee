use super::{DevicePathParser, DeviceSubTypeParser};
use anyhow::{anyhow, bail, Result};
use scroll::{Pread, LE};

/// Parser for Type 2 - ACPI Device Path.
/// Define in section 10.3.3 of <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#acpi-device-path>
enum AcpiSubType {
    Acpi,
    // Add more subtype parsers here as needed
}

impl AcpiSubType {
    fn from_u8(sub_type: u8) -> Result<Self> {
        match sub_type {
            0x01 => Ok(AcpiSubType::Acpi),
            _ => Err(anyhow!("Unknown ACPI subtype: {:#04x}", sub_type)),
        }
    }

    fn parse(&self, data: &[u8]) -> Result<String> {
        let parser: &dyn DeviceSubTypeParser = match self {
            AcpiSubType::Acpi => &AcpiSubTypeParser,
        };

        parser.parse(data)
    }
}

pub struct AcpiParser;

impl DevicePathParser for AcpiParser {
    fn parse(&self, sub_type: u8, data: &[u8]) -> Result<String> {
        AcpiSubType::from_u8(sub_type).and_then(|path| path.parse(data))
    }
}

pub struct AcpiSubTypeParser;

impl DeviceSubTypeParser for AcpiSubTypeParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() < size_of::<u64>() {
            bail!("ACPI sub type data length must be at least 8 bytes");
        }
        let mut index = 0;
        let hid: u32 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read hid: {:?}", e))?;
        let uid: u32 = data
            .gread_with(&mut index, LE)
            .map_err(|e| anyhow::anyhow!("Failed to read uid: {:?}", e))?;

        let vendor = hid & 0xFFFF;

        let vendor1 = ((vendor >> 10) & 0x1F) as u8 + b'@';
        let vendor2 = ((vendor >> 5) & 0x1F) as u8 + b'@';
        let vendor3 = (vendor & 0x1F) as u8 + b'@';

        let device = hid >> 16;

        let hid_formatted = format!(
            "{}{}{}{:04X}",
            vendor1 as char, vendor2 as char, vendor3 as char, device
        );

        Ok(format!("ACPI({},{})", hid_formatted, uid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::acpi(1, b"d041030a00000000", "ACPI(PNP0A03,0)")]
    #[case::acpi(1, b"d041030a02000000", "ACPI(PNP0A03,2)")]
    fn test_formatter(#[case] sub_type: u8, #[case] data: &[u8], #[case] expected_result: &str) {
        let vendor_data = hex::decode(data).unwrap();
        let actual = AcpiParser.parse(sub_type, &vendor_data);
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), expected_result);
    }

    #[rstest]
    #[case::acpi_expanded(2, "Unknown ACPI subtype: 0x02")]
    #[case::acpi_adr(3, "Unknown ACPI subtype: 0x03")]
    fn unsupported_test(#[case] sub_type: u8, #[case] expected_msg: &str) {
        let actual = AcpiParser.parse(sub_type, b"0000");
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err().to_string(), expected_msg);
    }
}
