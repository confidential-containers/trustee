use crate::ccel::tcg_enum::{TcgAlgorithm, TcgEventType};
use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use scroll::{Pread, LE};
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::HashMap;
use std::convert::TryFrom;

pub mod ccel;

pub const GUID_SIZE: usize = 16;

#[derive(Clone, Serialize)]
pub struct CcEventLog {
    #[serde(rename = "uefi_event_logs")]
    pub log: Vec<EventlogEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventlogEntry {
    pub details: EventDetails,
    pub digests: Vec<ElDigest>,
    pub event: String,
    pub index: u32,
    #[serde(rename = "type_name")]
    pub event_type: TcgEventType,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElDigest {
    pub alg: TcgAlgorithm,
    #[serde(serialize_with = "serialize_digest_as_hex")]
    pub digest: Vec<u8>,
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

#[derive(Debug, Clone)]
pub struct ReferenceMeasurement {
    pub index: u32,
    pub algorithm: TcgAlgorithm,
    pub reference: Vec<u8>,
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

impl CcEventLog {
    pub fn replay_and_match(&self, data: Vec<ReferenceMeasurement>) -> Result<()> {
        let digest_map = collect_digests_by_index(&self.log);

        for item in data.iter() {
            let calculated_ccel_rtmr = replay(&digest_map, item.index, item.algorithm)?;
            if calculated_ccel_rtmr != item.reference {
                bail!(
                    "CCEL eventlog does not pass RTMR [{}] check. CCEL value: {}, Quote value: {}",
                    item.index,
                    hex::encode(calculated_ccel_rtmr),
                    hex::encode(&item.reference)
                );
            }
        }
        Ok(())
    }
}

fn collect_digests_by_index(ccel: &[EventlogEntry]) -> HashMap<u32, Vec<ElDigest>> {
    let mut result: HashMap<u32, Vec<ElDigest>> = HashMap::new();

    for entry in ccel.iter() {
        let digests = result.entry(entry.index).or_default();
        for digest in entry.digests.iter() {
            digests.push(digest.clone());
        }
    }

    result
}

fn replay(
    digest_map: &HashMap<u32, Vec<ElDigest>>,
    index: u32,
    alg: TcgAlgorithm,
) -> Result<Vec<u8>> {
    let digest_size = alg.get_digest_size(alg)?;
    let mut materials = vec![0u8; digest_size];

    if let Some(digests) = digest_map.get(&index) {
        for digest in digests.iter().filter(|d| d.alg == alg) {
            materials = accumulate_hash(alg, materials, &digest.digest)?;
        }
    }

    Ok(materials)
}

fn accumulate_hash(alg: TcgAlgorithm, materials: Vec<u8>, digest: &[u8]) -> Result<Vec<u8>> {
    let result = match alg {
        TcgAlgorithm::Sha256 => hash_with::<Sha256>(&materials, digest),
        TcgAlgorithm::Sha384 => hash_with::<Sha384>(&materials, digest),
        TcgAlgorithm::Sha512 => hash_with::<Sha512>(&materials, digest),
        _ => bail!("Unsupported Hash algorithm {:?}", alg),
    };

    Ok(result)
}

fn hash_with<D: Digest + Default>(materials: &[u8], digest: &[u8]) -> Vec<u8> {
    let mut hasher = D::default();
    hasher.update(materials);
    hasher.update(digest);
    hasher.finalize().to_vec()
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
    use crate::ccel::tcg_enum::TcgAlgorithm;
    use crate::CcEventLog;
    use assert_json_diff::assert_json_eq;
    use rstest::rstest;
    use std::fs;
    use std::str::from_utf8;

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

    #[rstest]
    #[case("./test_data/CCEL_data",
        b"2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4",
        b"0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    #[case("./test_data/CCEL_data_ovmf",
        b"8566f998798db09443b244c62de9a3041fb02e2e6936c4396d784bba2e90177329ec5aba3bb484404f2ab9cc90abe193",
        b"775b9f6bfe99f8a31396f0d0218e67ffa796d3b96ccf961cbb0deba48c79c00f082cda1a5567c1c16305f1fc210c13c6",
        b"94eaf7a7bf398ed8d888c91057ae0261802e4f3df084213a76ca7f0b5055ac9d2241de43cd58d9e8b49c503bbf25f34a",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    #[case("./test_data/CCEL_data_grub",
        b"cec0a104f691f60da2387fea3c2de00c4ac035e2bb479ff02edcce69039d9e9907f0b3e55031da3dc7038f423adebd79",
        b"6c289e0c62182d41ebe97bdbc9872d10998a08eaa86adcdc684001a363207ee72942c7522cdf00a4bbc3d784bed7b670",
        b"08919d017ba0e52cd6d966351c7de16fe76c1d3d3d3da4554239e4c7d16cb8b82a94e7eaea3a0e6e18eb690b999fd31e",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    #[case("./test_data/CCEL_data_gcp",
        b"3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f",
        b"204d49f78d29918fe7b2f694e76653861a0c2a018987d2c3a54266eff737232524cf0af68c4d180e2f8c2c0937f21967",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    #[case::gke_with_rtmr_0_no_action("./test_data/CCEL_data_grub_gke",
        b"bc9945139042cf2cc75caf920aa57f14884ecfd7e893bccc51250c8ce90eb53ce72741e6adaa18183eb1331a87d4544a",
        b"c17cb288a4dee302bb9ed8d27257a168f3264ad68cab53757f37eeaa7039657fa887cad65cf910e0fdc435ff110f8a7b",
        b"334aeba2c985f8886cea97d1ecffbd512769d528b9a94009583db667ad7d2faa7d37fa145d75b192ceee2d2f10b2eb6d",
        b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    )]
    fn test_rtmr_integrity(
        #[case] test_data: &str,
        #[case] rtmr0: &[u8],
        #[case] rtmr1: &[u8],
        #[case] rtmr2: &[u8],
        #[case] rtmr3: &[u8],
    ) {
        let ccel_bin = fs::read(test_data).unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();

        let compare_obj: Vec<ReferenceMeasurement> = vec![
            ReferenceMeasurement {
                index: 1,
                algorithm: TcgAlgorithm::Sha384,
                reference: hex::decode(rtmr0).unwrap(),
            },
            ReferenceMeasurement {
                index: 2,
                algorithm: TcgAlgorithm::Sha384,
                reference: hex::decode(rtmr1).unwrap(),
            },
            ReferenceMeasurement {
                index: 3,
                algorithm: TcgAlgorithm::Sha384,
                reference: hex::decode(rtmr2).unwrap(),
            },
            ReferenceMeasurement {
                index: 4,
                algorithm: TcgAlgorithm::Sha384,
                reference: hex::decode(rtmr3).unwrap(),
            },
        ];

        let rtmr_result = ccel.replay_and_match(compare_obj);

        assert!(rtmr_result.is_ok());
    }

    #[rstest]
    #[case("./test_data/CCEL_data_gcp",
        b"3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304d",
        b"204d49f78d29918fe7b2f694e76653861a0c2a018987d2c3a54266eff737232524cf0af68c4d180e2f8c2c0937f21967",
        true,
        String::from("3300980705adf09d28b707b79699d9874892164280832be2c386a715b6e204e0897fb564a064f810659207ba862b304f"
        )
    )]
    #[case("./test_data/CCEL_data",
        b"2dc712306a963eadb894ad47dbaa17df44814151555aee11cbb843becca88950ffd079664902e6f22c66f7c8213543f4",
        b"2fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf",
        false,
        String::from("0fa3be56af61208bbd179dc7b124988eb929319154663c539d6f46445ecac2fec287075047ff7bd1922829fec28cd3cf"
        )
    )]
    fn test_rtmr_integrity_error(
        #[case] test_data: &str,
        #[case] rtmr0: &[u8],
        #[case] rtmr1: &[u8],
        #[case] first_wrong: bool,
        #[case] ccel_wrong_rtmr_value: String,
    ) {
        let ccel_bin = fs::read(test_data).unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();

        let compare_obj: Vec<ReferenceMeasurement> = vec![
            ReferenceMeasurement {
                index: 1,
                algorithm: TcgAlgorithm::Sha384,
                reference: hex::decode(rtmr0).unwrap(),
            },
            ReferenceMeasurement {
                index: 2,
                algorithm: TcgAlgorithm::Sha384,
                reference: hex::decode(rtmr1).unwrap(),
            },
        ];

        let rtmr_result = ccel.replay_and_match(compare_obj);

        assert!(rtmr_result.is_err());

        let wrong_index = if first_wrong { 1 } else { 2 };
        let expected = if first_wrong { rtmr0 } else { rtmr1 };
        let expected_err_msg = format!(
            "CCEL eventlog does not pass RTMR [{}] check. CCEL value: {}, Quote value: {}",
            wrong_index,
            ccel_wrong_rtmr_value,
            from_utf8(expected).expect("utf8 error"),
        );

        assert_eq!(rtmr_result.unwrap_err().to_string(), expected_err_msg);
    }
}
