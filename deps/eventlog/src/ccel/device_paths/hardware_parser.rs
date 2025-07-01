use super::{DevicePathParser, DeviceSubTypeParser};
use anyhow::{anyhow, bail, Result};

/// Parser for Type 1 - Hardware Device Path.
/// Define in section 10.3.2 of <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#hardware-device-path>
enum HardwareSubType {
    Pci,
    // Add more subtype parsers here as needed
}

impl HardwareSubType {
    fn from_u8(sub_type: u8) -> Result<Self> {
        match sub_type {
            0x01 => Ok(HardwareSubType::Pci),
            _ => Err(anyhow!("Unknown Hardware subtype: {:#04x}", sub_type)),
        }
    }

    fn parse(&self, data: &[u8]) -> Result<String> {
        let parser: &dyn DeviceSubTypeParser = match self {
            HardwareSubType::Pci => &PciParser,
        };

        parser.parse(data)
    }
}

pub struct HardwareParser;

impl DevicePathParser for HardwareParser {
    fn parse(&self, sub_type: u8, data: &[u8]) -> Result<String> {
        HardwareSubType::from_u8(sub_type).and_then(|path| path.parse(data))
    }
}

pub struct PciParser;

impl DeviceSubTypeParser for PciParser {
    fn parse(&self, data: &[u8]) -> Result<String> {
        if data.len() < 2 {
            bail!("PCI data is too short");
        }
        let func_num = data[0];
        let device_num = data[1];
        Ok(format!("Pci({},{})", func_num, device_num))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(1, b"0001", "Pci(0,1)")]
    #[case(1, b"0000", "Pci(0,0)")]
    #[case(1, b"0004", "Pci(0,4)")]
    fn test_formatter(#[case] sub_type: u8, #[case] data: &[u8], #[case] expected_result: &str) {
        let vendor_data = hex::decode(data).unwrap();
        let actual = HardwareParser.parse(sub_type, &vendor_data);
        assert!(actual.is_ok());
        assert_eq!(actual.unwrap(), expected_result);
    }

    #[rstest]
    #[case::pc_card(2, "Unknown Hardware subtype: 0x02")]
    #[case::memory_mapped(3, "Unknown Hardware subtype: 0x03")]
    #[case::vendor(4, "Unknown Hardware subtype: 0x04")]
    #[case::controller(5, "Unknown Hardware subtype: 0x05")]
    #[case::bmc(6, "Unknown Hardware subtype: 0x06")]
    fn unsupported_test(#[case] sub_type: u8, #[case] expected_msg: &str) {
        let actual = HardwareParser.parse(sub_type, b"0000");
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err().to_string(), expected_msg);
    }
}
