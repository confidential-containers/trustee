// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{EventDataParser, EventDetails};
use crate::ccel::device_paths::DevicePath;
use anyhow::{bail, Result};

pub struct EvBootServicesAppParser;

/// Parser for EV_IPL event EV_EFI_BOOT_SERVICES_APPLICATION
/// Defined in section 10.2.3 of <https://trustedcomputinggroup.org/wp-content/uploads/TCG_PCClient_PFP_r1p05_v23_pub.pdf>
/// ```text
/// UEFI_IMAGE_LOAD_EVENT {
///     UEFI_PHYSICAL_ADDRESS ImageLocationInMemory; // PE/COFF image
///     UINT64 ImageLengthInMemory;
///     UINT64 ImageLinkTimeAddress;
///     UINT64 LengthOfDevicePath;
///     BYTE DevicePath[LengthOfDevicePath]; // See UEFI spec Section EFI Device Path Protocol
/// }
/// ```
/// UEFI device path specification: <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#generic-device-path-node-structure>
impl EventDataParser for EvBootServicesAppParser {
    fn parse(&self, data: Vec<u8>) -> Result<EventDetails> {
        let dev_path_offset_start = size_of::<u64>() * 3;
        let dev_path_offset_end = dev_path_offset_start + size_of::<u64>();

        if data.len() < dev_path_offset_end {
            bail!(
                "Data is too short: expected at least {} bytes",
                dev_path_offset_end
            );
        }

        let dev_path_len =
            u64::from_le_bytes(data[dev_path_offset_start..dev_path_offset_end].try_into()?);

        if dev_path_len == 0 {
            return Ok(EventDetails::empty());
        }

        // Calculate the start of the device path and ensure data length
        let dev_path_start = dev_path_offset_end;
        let dev_path_end = dev_path_start + (dev_path_len as usize - size_of::<u32>());

        if data.len() < dev_path_end {
            bail!("Data is shorter than claimed by dev_path_offset")
        }

        let device_path_bytes = &data[dev_path_start..dev_path_end];
        let result_data = EventDetails::empty();

        if device_path_bytes.len() < size_of::<u32>() {
            bail!("Remaining device path is shorter than 4 bytes");
        }

        get_nested_paths(device_path_bytes, result_data)
    }
}

/// Reads nested device paths which should follow section 10.3.1 of <https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#generic-device-path-node-structure>
fn get_nested_paths(device_path_bytes: &[u8], mut result: EventDetails) -> Result<EventDetails> {
    let efi_type = device_path_bytes[0];
    let efi_sub_type = device_path_bytes[1];
    let efi_length = u16::from_le_bytes(device_path_bytes[2..4].try_into()?) as usize;

    if device_path_bytes.len() < efi_length {
        bail!("Data is too short: expected at least {} bytes", efi_length);
    }

    let vendor_data_raw = &device_path_bytes[4..efi_length];

    let device_path = &device_path_bytes[efi_length..];

    result
        .device_paths
        .get_or_insert_with(Vec::new)
        .push(print_path(efi_type, efi_sub_type, vendor_data_raw));

    if device_path.is_empty() {
        return Ok(result);
    }

    get_nested_paths(device_path, result)
}

/// Prints device path based on type and subtype.
/// For unsupported paths default formatter will be used: Path(type,subtype,hex_data).
fn print_path(efi_type: u8, efi_sub_type: u8, vendor_data: &[u8]) -> String {
    DevicePath::from_u8(efi_type)
        .and_then(|dev_path| dev_path.parse(efi_sub_type, vendor_data))
        .unwrap_or_else(|_| {
            format!(
                "Path({},{},{})",
                efi_type,
                efi_sub_type,
                hex::encode(vendor_data)
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("1800b37c0000000000a2a5000000000000000000000000002a000000000000000403140072f728144ab61e44b8c39ebdd7f893c7040412006b00650072006e0065006c0000007fff0400",
        EventDetails { string: None, unicode_name: None, unicode_name_length: None, variable_data: None, variable_data_length: None, variable_name: None, device_paths: Some(vec!["VenMedia(1428F772-B64A-441E-B8C3-9EBDD7F893C7,)".to_string(), "File(kernel)".to_string()]), data: None }
    )]
    #[case("18406a7d0000000008c00e00000000000000000000000000820000000000000002010c00d041030a0000000001010600000101010600000001010600000101010600000004012a000f000000002800000000000000500300000000005e27f1007553d5439eb5de2add4c99320202040430005c004500460049005c0042004f004f0054005c0042004f004f0054005800360034002e0045004600490000007fff0400",
        EventDetails { string: None, unicode_name: None, unicode_name_length: None, variable_data: None, variable_data_length: None, variable_name: None, device_paths: Some(vec!["ACPI(PNP0A03,0)".to_string(), "Pci(0,1)".to_string(), "Pci(0,0)".to_string(), "Pci(0,1)".to_string(), "Pci(0,0)".to_string(), "HD(15,GPT,00F1275E-5375-43D5-9EB5-DE2ADD4C9932,0x2800,0x35000)".to_string(), "File(\\EFI\\BOOT\\BOOTX64.EFI)".to_string()]), data: None }
    )]
    #[case(
        "009d9b7a000000008879e4000000000000000000000000000000000000000000",
       EventDetails { string: None, unicode_name: None, unicode_name_length: None, variable_data: None, variable_data_length: None, variable_name: None, device_paths: None, data: None }
    )]
    #[case("0060d8570100000068a90401000000000000000000000000180000000000000004031400f8d1c555cd04b5468a20e56cbb3052d07fff0400",
       EventDetails { string: None, unicode_name: None, unicode_name_length: None, variable_data: None, variable_data_length: None, variable_name: None, device_paths: Some(vec!["VenMedia(55C5D1F8-04CD-46B5-8A20-E56CBB3052D0,)".to_string()]), data: None }
    )]
    fn test_boot_services_parser(#[case] test_data: &str, #[case] expected_result: EventDetails) {
        let parser = EvBootServicesAppParser;
        let actual_result = parser.parse(hex::decode(test_data).unwrap());

        assert!(actual_result.is_ok());
        assert_eq!(actual_result.unwrap(), expected_result);
    }
}
