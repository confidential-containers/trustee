// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::device_paths;
use anyhow::{anyhow, Result};
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

pub enum DevicePath {
    /// Type 1 -> Hardware Device Path
    Hardware,
    /// Type 2 -> ACPI Device Path
    Acpi,
    /// Type 3 -> Messaging Device Path
    Messaging,
    /// Type 4 -> Media Device Path
    Media,
    /// Type 5 -> BIOS Boot Specification Device Path
    BiosBootSpec,
}

impl DevicePath {
    pub fn from_u8(efi_type: u8) -> Result<Self> {
        match efi_type {
            0x01 => Ok(DevicePath::Hardware),
            0x02 => Ok(DevicePath::Acpi),
            0x03 => Ok(DevicePath::Messaging),
            0x04 => Ok(DevicePath::Media),
            0x05 => Ok(DevicePath::BiosBootSpec),
            _ => Err(anyhow!("Unknown Device Path Type: {:#04x}", efi_type)),
        }
    }

    pub fn parse(&self, efi_sub_type: u8, data: &[u8]) -> Result<String> {
        let parser: &dyn DevicePathParser = match self {
            DevicePath::Hardware => &HardwareParser,
            DevicePath::Acpi => &AcpiParser,
            DevicePath::Messaging => &MessagingParser,
            DevicePath::Media => &MediaParser,
            DevicePath::BiosBootSpec => &BiosBootSpecParser,
        };

        parser.parse(efi_sub_type, data)
    }
}

/// Trait for parsing text device nodes described in specification:
/// <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#text-device-node-reference>
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
        let actual =
            DevicePath::from_u8(efi_type).and_then(|dev_path| dev_path.parse(efi_sub_type, data));
        assert!(actual.is_err());
        assert_eq!(actual.unwrap_err().to_string(), expected_msg);
    }
}
