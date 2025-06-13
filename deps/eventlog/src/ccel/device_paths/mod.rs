use super::device_paths;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::LazyLock;
pub mod acpi_parser;
pub mod bios_boot_spec_parser;
pub mod hardware_parser;
pub mod media_parser;
pub mod messaging_parser;

pub(crate) use device_paths::acpi_parser::AcpiParser;
pub(crate) use device_paths::bios_boot_spec_parser::BiosBootSpecParser;
pub(crate) use device_paths::hardware_parser::HardwareParser;
pub(crate) use device_paths::media_parser::MediaParser;
pub(crate) use device_paths::messaging_parser::MessagingParser;

/// Handlers for parsing text device nodes described in specification:
/// <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#text-device-node-reference>
/// Type 1 -> Hardware Device Path
/// Type 2 -> ACPI Device Path
/// Type 3 -> Messaging Device Path
/// Type 4 -> Media Device Path
/// Type 5 -> BIOS Boot Specification Device Path
static DEVICE_PATH_HANDLERS: LazyLock<HashMap<u8, Box<dyn DevicePathParser + Send + Sync>>> =
    LazyLock::new(|| {
        let mut handlers: HashMap<u8, Box<dyn DevicePathParser + Send + Sync>> = HashMap::new();
        handlers.insert(0x01, Box::new(HardwareParser));
        handlers.insert(0x02, Box::new(AcpiParser));
        handlers.insert(0x03, Box::new(MessagingParser));
        handlers.insert(0x04, Box::new(MediaParser));
        handlers.insert(0x05, Box::new(BiosBootSpecParser));
        handlers
    });

pub struct DevicePathDispatcher;

impl DevicePathDispatcher {
    pub fn parse(efi_type: u8, efi_sub_type: u8, data: &[u8]) -> Result<String> {
        DEVICE_PATH_HANDLERS
            .get(&efi_type)
            .ok_or_else(|| anyhow!("Unknown Device Path Type: {:#04x}", efi_type))?
            .parse(efi_sub_type, data)
    }
}

pub trait DevicePathParser {
    fn parse(&self, sub_type: u8, data: &[u8]) -> Result<String>;
}

pub trait DeviceSubTypeParser {
    fn parse(&self, data: &[u8]) -> Result<String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::unknown(6, 1, b"0000", "Unknown Device Path Type: 0x06")]
    fn unsupported_test(
        #[case] efi_type: u8,
        #[case] efi_sub_type: u8,
        #[case] data: &[u8],
        #[case] expected_msg: &str,
    ) {
        let actual = DevicePathDispatcher::parse(efi_type, efi_sub_type, data);
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err().to_string(), expected_msg);
    }
}
