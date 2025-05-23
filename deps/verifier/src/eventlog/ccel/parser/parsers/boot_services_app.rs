use crate::eventlog::ccel::parser::DescriptionParser;
use crate::eventlog::ccel::EventDetails;
use anyhow::{Error, Result};
use byteorder::{ByteOrder, LittleEndian};
pub struct EvBootServicesAppParser;

impl DescriptionParser for EvBootServicesAppParser {
    fn parse_description(&self, data: Vec<u8>) -> Result<EventDetails, Error> {
        // ImageLocationInMemory + ImageLengthInMemory + ImageLinkTimeAddress (24) and 8 for length
        let length_of_device_path = u64::from_le_bytes(data[24..32].try_into()?);

        if length_of_device_path == 0 {
            return Ok(EventDetails::empty());
        }

        // Calculate the start of the device path and ensure data length
        let device_path_start = 32;
        let device_path_end_header = 4;
        let device_path_end =
            device_path_start + (length_of_device_path - device_path_end_header) as usize;

        if data.len() <= device_path_end {
            return Ok(EventDetails::empty());
        }

        let device_path_bytes = &data[device_path_start..device_path_end];
        let result_data = EventDetails::empty();
        get_nested_data(device_path_bytes, result_data)
    }
}

fn get_nested_data(
    device_path_bytes: &[u8],
    mut result: EventDetails,
) -> Result<EventDetails, Error> {
    let efi_type = device_path_bytes[0];
    let efi_sub_type = device_path_bytes[1];
    let efi_length = u16::from_le_bytes(device_path_bytes[2..4].try_into()?);
    let vendor_data_raw = &device_path_bytes[4..efi_length as usize];

    let device_path = &device_path_bytes[efi_length as usize..];

    let vendor_data = recover_string(vendor_data_raw);
    let pretty = print_path(efi_type, efi_sub_type, vendor_data.clone());
    result
        .device_paths
        .get_or_insert_with(Vec::new)
        .push(pretty);
    result.unicode_name = Some(vendor_data.clone());
    result.unicode_name_length = Some(vendor_data.len() as u64);

    // https://uefi.org/specs/UEFI/2.10/10_Protocols_Device_Path_Protocol.html#generic-device-path-node-structure
    if device_path.is_empty() {
        return Ok(result);
    }

    get_nested_data(device_path, result)
}

fn print_path(efi_type: u8, efi_sub_type: u8, vendor_data: String) -> String {
    if efi_type == 1 && efi_sub_type == 1 {
        let result = hex::decode(vendor_data).unwrap();
        return format!("Pci({},{})", result[0], result[1]);
    }
    if efi_type == 4 && efi_sub_type == 4 {
        return format!("File({})", vendor_data);
    }

    format!("Path({},{},{})", efi_type, efi_sub_type, vendor_data)
}

fn recover_string(vendor_data_raw: &[u8]) -> String {
    if !is_utf16_encoded_text(vendor_data_raw) {
        return hex::encode(vendor_data_raw);
    };

    let device_path: Vec<u16> = vendor_data_raw
        .chunks(2)
        .map(LittleEndian::read_u16)
        .take_while(|&x| x != 0)
        .collect();

    String::from_utf16(&device_path).expect("Could not convert data to string")
}

fn is_utf16_encoded_text(data: &[u8]) -> bool {
    if data.len() < 2 || data.len() % 2 != 0 {
        return false;
    }

    let utf16: Vec<u16> = data
        .chunks(2)
        .map(LittleEndian::read_u16)
        .take_while(|&x| x != 0)
        .collect();

    if let Ok(decoded) = String::from_utf16(&utf16) {
        let printable_chars = decoded
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count();

        let ratio = printable_chars as f32 / decoded.len().max(1) as f32;
        return ratio > 0.9;
    }

    false
}
