use anyhow::{anyhow, Result};
use byteorder::{ByteOrder, LittleEndian};

pub(crate) fn get_next_bytes<'a>(
    data: &'a [u8],
    index: &mut usize,
    count: usize,
) -> Result<&'a [u8], anyhow::Error> {
    if *index + count > data.len() {
        return Err(anyhow!(format!(
            "Out of bounds: trying to read {} bytes at index {}, but only {} bytes available.",
            count,
            *index,
            data.len() - *index
        )));
    }

    let slice = &data[*index..*index + count];
    *index += count;
    Ok(slice)
}

pub(crate) fn read_u16_le(data: &[u8], index: &mut usize) -> Result<u16, anyhow::Error> {
    let bytes = get_next_bytes(data, index, size_of::<u16>())?;
    Ok(LittleEndian::read_u16(bytes))
}

pub(crate) fn read_u32_le(data: &[u8], index: &mut usize) -> Result<u32, anyhow::Error> {
    let bytes = get_next_bytes(data, index, size_of::<u32>())?;
    Ok(LittleEndian::read_u32(bytes))
}

pub(crate) fn read_u64_le(data: &[u8], index: &mut usize) -> Result<u64, anyhow::Error> {
    let bytes = get_next_bytes(data, index, size_of::<u64>())?;
    Ok(LittleEndian::read_u64(bytes))
}

// Recover string or return hex value for strings which contains non-graphical data
pub(crate) fn recover_string(vendor_data_raw: &[u8]) -> String {
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

// Helper utility to detect if utf 16 data contains meaningful data
pub(crate) fn is_utf16_encoded_text(data: &[u8]) -> bool {
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
