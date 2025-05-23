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
