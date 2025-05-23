use crate::ccel::tcg_enum::{TcgAlgorithm, TcgEventType};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use scroll::{Pread, LE};
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryFrom;

pub mod ccel;

#[derive(Clone, Serialize)]
pub struct CcEventLog {
    #[serde(rename = "uefi_event_logs")]
    pub log: Vec<EventlogEntry>,
}

#[derive(Debug, Clone)]
pub struct EventlogEntry {
    pub index: u32,
    pub event_type: TcgEventType,
    pub digests: Vec<ElDigest>,
    pub event: String,
    pub details: EventDetails,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct EventDetails {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub string: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicode_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unicode_name_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variable_data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variable_data_length: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variable_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_paths: Option<Vec<String>>,
    #[serde(
        serialize_with = "serialize_json_string_vec",
        skip_serializing_if = "Option::is_none"
    )]
    pub data: Option<Vec<String>>,
}

impl EventDetails {
    pub fn from_string(s: String) -> Self {
        Self {
            string: Some(s),
            unicode_name: None,
            unicode_name_length: None,
            variable_data: None,
            variable_data_length: None,
            variable_name: None,
            device_paths: None,
            data: None,
        }
    }

    pub fn empty() -> Self {
        Self {
            string: None,
            unicode_name: None,
            unicode_name_length: None,
            variable_data: None,
            variable_data_length: None,
            variable_name: None,
            device_paths: None,
            data: None,
        }
    }
}

impl Serialize for EventlogEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("EventlogEntry", 6)?;
        state.serialize_field("details", &self.details)?;
        state.serialize_field("digests", &self.digests)?;
        state.serialize_field("event", &self.event)?;
        state.serialize_field("index", &self.index)?;
        state.serialize_field("type", &format!("0x{:08X}", self.event_type as u32))?;
        state.serialize_field("type_name", &self.event_type.format_name())?;
        state.end()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ElDigest {
    pub alg: TcgAlgorithm,
    #[serde(serialize_with = "serialize_digest_as_hex")]
    pub digest: Vec<u8>,
}

fn serialize_digest_as_hex<S>(digest: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(digest))
}

fn serialize_json_string_vec<S>(vec: &Option<Vec<String>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match vec {
        Some(inner_vec) => {
            let mut seq = serializer.serialize_seq(Some(inner_vec.len()))?;
            for json_str in inner_vec {
                let json_value: Value =
                    serde_json::from_str(json_str).map_err(serde::ser::Error::custom)?;
                seq.serialize_element(&json_value)?;
            }
            seq.end()
        }
        None => serializer.serialize_none(),
    }
}

impl TryFrom<Vec<u8>> for CcEventLog {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self> {
        let mut index = 0;
        let mut event_log = Vec::new();
        let mut digest_size_map = HashMap::new();

        parse_initial_entry(&data, &mut index, &mut digest_size_map)?;

        while index < data.len() {
            let entry_opt;
            (entry_opt, index) = parse_eventlog_entry(&data, index, &mut digest_size_map)?;
            if let Some(entry) = entry_opt {
                event_log.push(entry);
            } else if index == 0 {
                break;
            }
        }

        Ok(CcEventLog { log: event_log })
    }
}

/// Parse the first event in the event log which is the informational event
/// TCG_EfiSpecIdEvent (See Section 10.4.5.1 Specification ID Version Event)
/// Docs: <https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub-3.pdf>
fn parse_initial_entry(
    data: &[u8],
    index: &mut usize,
    digest_size_map: &mut HashMap<TcgAlgorithm, u16>,
) -> Result<()> {
    let _pcr_index = data
        .gread_with::<u32>(index, LE)
        .map_err(|_| anyhow!("Cannot read PCR index"))?;
    let event_type_num = data
        .gread_with::<u32>(index, LE)
        .map_err(|_| anyhow!("Cannot read event type number"))?;

    let event_type = TcgEventType::try_from(event_type_num)
        .map_err(|_| anyhow!("Unknown event type detected: {:#x}", event_type_num))?;

    *index += 20;
    let event_data_size = data
        .gread_with::<u32>(index, LE)
        .map_err(|_| anyhow!("Cannot read event data size"))?;

    if TcgEventType::EvNoAction == event_type {
        let start = *index;
        let end = start
            .checked_add(event_data_size as usize)
            .ok_or_else(|| anyhow!("Overflow in calculating digest_data range"))?;
        let digest_data = data
            .get(start..end)
            .ok_or_else(|| anyhow!("Out of bounds while reading digest_data"))?;
        *index = end;
        let actual_size = parse_digest_sizes(digest_data, digest_size_map)?;
        if actual_size != event_data_size as usize {
            bail!("Unexpected data size consumed for detecting digests");
        }
    }

    Ok(())
}

fn parse_eventlog_entry(
    data: &[u8],
    mut index: usize,
    digest_size_map: &mut HashMap<TcgAlgorithm, u16>,
) -> Result<(Option<EventlogEntry>, usize)> {
    let stop_flag = data
        .gread_with::<u64>(&mut index, LE)
        .map_err(|e| anyhow::anyhow!("Failed to read potential stop flag: {:?}", e))?;
    index -= size_of::<u64>();
    if stop_flag == 0xFFFFFFFFFFFFFFFF || stop_flag == 0x0000000000000000 {
        return Ok((None, 0));
    }

    let target_measurement_registry = data
        .gread_with::<u32>(&mut index, LE)
        .map_err(|_| anyhow!("Cannot read target measurement registry"))?;

    let event_type_num = data
        .gread_with::<u32>(&mut index, LE)
        .map_err(|_| anyhow!("Cannot read event type number"))?;

    let event_type = TcgEventType::try_from(event_type_num)
        .map_err(|_| anyhow!("Unknown event type detected: {:#x}", event_type_num))?;

    let digests;
    (digests, index) = parse_digests(data, index, digest_size_map)?;

    let event_data_size = data
        .gread_with::<u32>(&mut index, LE)
        .map_err(|_| anyhow!("Cannot read event data size"))? as usize;

    if data.len() < event_data_size {
        bail!(
            "Data is too short: expected at least {} bytes",
            event_data_size
        );
    }

    let event_data_raw = data[index..(index + event_data_size)].to_vec();
    index += event_data_size;

    let event = STANDARD.encode(&event_data_raw);
    let event_result = event_type.get_parser().parse(event_data_raw)?;

    Ok((
        Some(EventlogEntry {
            index: target_measurement_registry,
            event_type,
            digests,
            event,
            details: event_result,
        }),
        index,
    ))
}

fn parse_digest_sizes(
    data: &[u8],
    digest_size_map: &mut HashMap<TcgAlgorithm, u16>,
) -> Result<usize> {
    let mut struct_index = 24;
    let algo_size = data
        .gread_with::<u32>(&mut struct_index, LE)
        .map_err(|_| anyhow!("Cannot read algorithm array size"))?;

    for _ in 0..algo_size {
        let algo_id = data
            .gread_with::<u16>(&mut struct_index, LE)
            .map_err(|_| anyhow!("Cannot read algorithm id"))?;
        let size = data
            .gread_with::<u16>(&mut struct_index, LE)
            .map_err(|_| anyhow!("Cannot read algorithm size"))?;

        let algorithm = TcgAlgorithm::try_from(algo_id as u32)
            .map_err(|_| anyhow!("Unknown algorithm type detected: {:x}", algo_id))?;

        digest_size_map.insert(algorithm, size);
    }

    let vendor_size = data[struct_index] as usize;
    struct_index += vendor_size + 1;
    Ok(struct_index)
}

fn parse_digests(
    data: &[u8],
    mut index: usize,
    digest_size_map: &HashMap<TcgAlgorithm, u16>,
) -> Result<(Vec<ElDigest>, usize)> {
    let digest_count = data
        .gread_with::<u32>(&mut index, LE)
        .map_err(|_| anyhow!("Cannot read digest count"))?;

    let mut digests = Vec::new();
    for _ in 0..digest_count {
        let algo_id = data
            .gread_with::<u16>(&mut index, LE)
            .map_err(|_| anyhow!("Cannot read algorithm id"))?;

        let algorithm = TcgAlgorithm::try_from(algo_id as u32)
            .map_err(|_| anyhow!("Unknown algorithm type detected: {:x}", algo_id))?;

        let size = *digest_size_map
            .get(&algorithm)
            .ok_or_else(|| anyhow!("Missing digest size for algorithm: {:x}", algo_id))?
            as usize;

        let digest = data[index..index + size].to_vec();
        index += size;

        digests.push(ElDigest {
            alg: algorithm,
            digest,
        });
    }

    Ok((digests, index))
}

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use std::fs;

    #[rstest]
    #[case("./test_data/CCEL_data", "./test_data/CCEL_data_out.json")]
    #[case("./test_data/CCEL_data_ovmf", "./test_data/CCEL_data_ovmf_out.json")]
    #[case("./test_data/CCEL_data_grub", "./test_data/CCEL_data_grub_out.json")]
    #[case(
        "./test_data/CCEL_data_grub_gke",
        "./test_data/CCEL_data_grub_gke_out.json"
    )]
    fn test_query_digest(#[case] test_data: &str, #[case] expected_data: &str) {
        let ccel_bin = fs::read(test_data).expect("open test data");
        let ccel = CcEventLog::try_from(ccel_bin).expect("parse CCEL eventlog");
        let json = serde_json::to_value(&ccel).unwrap();

        let expected_json_str =
            fs::read_to_string(expected_data).expect("read expected json output failed");
        let expected: Value =
            serde_json::from_str(&expected_json_str).expect("parsing expected json failed");

        assert_json_eq!(expected, json);
    }
}
