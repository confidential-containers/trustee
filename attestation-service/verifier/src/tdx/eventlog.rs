use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use core::mem::size_of;
use eventlog_rs::Eventlog;
use std::convert::{TryFrom, TryInto};
use std::string::ToString;
use strum_macros::{Display, EnumString};

#[derive(Debug, Clone, EnumString, Display)]
pub enum MeasuredEntity {
    #[strum(serialize = "td_hob\0")]
    TdShim,
    #[strum(serialize = "td_payload\0")]
    TdShimKernel,
    #[strum(serialize = "td_payload_info\0")]
    TdShimKernelParams,
    #[strum(serialize = "k\0e\0r\0n\0e\0l\0")]
    TdvfKernel,
}

#[derive(Debug, Clone, Copy)]
pub struct Rtmr {
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

#[derive(Clone)]
pub struct CcEventLog {
    pub cc_events: Eventlog,
}

impl TryFrom<Vec<u8>> for CcEventLog {
    type Error = anyhow::Error;
    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self {
            cc_events: Eventlog::try_from(data)?,
        })
    }
}

impl CcEventLog {
    pub fn integrity_check(&self, rtmr_from_quote: Rtmr) -> Result<()> {
        let rtmr_eventlog = self.rebuild_rtmr()?;

        // Compare rtmr values from tdquote and EventLog acpi table
        if rtmr_from_quote.rtmr0 != rtmr_eventlog.rtmr0
            || rtmr_from_quote.rtmr1 != rtmr_eventlog.rtmr1
            || rtmr_from_quote.rtmr2 != rtmr_eventlog.rtmr2
            || rtmr_from_quote.rtmr3 != rtmr_eventlog.rtmr3
        {
            return Err(anyhow!(
                "RTMR values from TD quote is not equal with the values from EventLog\n"
            ));
        }

        Ok(())
    }

    fn rebuild_rtmr(&self) -> Result<Rtmr> {
        let mr_map = self.cc_events.replay_measurement_regiestry();

        let mr = Rtmr {
            rtmr0: mr_map.get(&1).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
            rtmr1: mr_map.get(&2).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
            rtmr2: mr_map.get(&3).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
            rtmr3: mr_map.get(&4).unwrap_or(&Vec::from([0u8; 48]))[0..48].try_into()?,
        };

        Ok(mr)
    }

    pub fn query_digest(&self, entity: MeasuredEntity) -> Option<String> {
        let event_desc_prefix = Self::generate_query_key_prefix(entity)?;

        for event_entry in self.cc_events.log.clone() {
            if event_entry.event_desc.len() < event_desc_prefix.len() {
                continue;
            }
            if &event_entry.event_desc[..event_desc_prefix.len()] == event_desc_prefix.as_slice() {
                let digest = &event_entry.digests[0].digest;
                return Some(hex::encode(digest));
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn query_event_data(&self, entity: MeasuredEntity) -> Option<Vec<u8>> {
        let event_desc_prefix = Self::generate_query_key_prefix(entity)?;

        for event_entry in self.cc_events.log.clone() {
            if event_entry.event_desc.len() < event_desc_prefix.len() {
                continue;
            }
            if &event_entry.event_desc[..event_desc_prefix.len()] == event_desc_prefix.as_slice() {
                return Some(event_entry.event_desc);
            }
        }
        None
    }

    #[allow(unused_assignments)]
    fn generate_query_key_prefix(entity: MeasuredEntity) -> Option<Vec<u8>> {
        let mut event_desc_prefix = Vec::new();
        match entity {
            MeasuredEntity::TdShimKernel => {
                // Event data is in UEFI_PLATFORM_FIRMWARE_BLOB2 format
                // Defined in TCG PC Client Platform Firmware Profile Specification section
                // 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
                let entity_name = entity.to_string();
                event_desc_prefix = vec![entity_name.as_bytes().len() as u8];
                event_desc_prefix.extend_from_slice(entity_name.as_bytes());
            }
            MeasuredEntity::TdvfKernel => {
                event_desc_prefix = entity.to_string().as_bytes().to_vec();
            }
            MeasuredEntity::TdShim | MeasuredEntity::TdShimKernelParams => {
                // Event data is in TD_SHIM_PLATFORM_CONFIG_INFO format
                // Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
                // link: https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md
                event_desc_prefix = entity.to_string().as_bytes().to_vec();
            }
        }
        Some(event_desc_prefix)
    }
}

/// Defined in TCG PC Client Platform Firmware Profile Specification section
/// 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
pub struct ParsedUefiPlatformFirmwareBlob2 {
    pub desc_len: u8,
    pub desc: Vec<u8>,
    pub blob_base: u64,
    pub blob_length: u64,
}

impl TryFrom<Vec<u8>> for ParsedUefiPlatformFirmwareBlob2 {
    type Error = anyhow::Error;

    fn try_from(data: Vec<u8>) -> Result<Self, Self::Error> {
        let desc_len = data[0] as usize;
        let desc = data[1..(desc_len + 1)].to_vec();
        let blob_base = (&data[(desc_len + 1)..(desc_len + 1 + size_of::<u64>())])
            .read_u64::<LittleEndian>()?;
        let blob_length = (&data
            [(desc_len + 1 + size_of::<u64>())..(desc_len + 1 + size_of::<u64>() * 2)])
            .read_u64::<LittleEndian>()?;

        Ok(Self {
            desc_len: data[0],
            desc,
            blob_base,
            blob_length,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_eventlog() {
        let ccel_bin = fs::read("./test_data/CCEL_data").unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();

        let _ = fs::write(
            "test_data/parse_eventlog_output.txt",
            format!("{}", &ccel.cc_events),
        );
    }

    #[test]
    fn test_rebuild_rtmr() {
        let ccel_bin = fs::read("./test_data/CCEL_data").unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();

        let rtmr_result = ccel.rebuild_rtmr();
        assert!(rtmr_result.is_ok());
        let rtmr = rtmr_result.unwrap();

        let output = format!(
            "RTMR[0]\n\t{}\nRTMR[1]\n\t{}\nRTMR[2]\n\t{}\nRTMR[3]\n\t{}",
            hex::encode(rtmr.rtmr0),
            hex::encode(rtmr.rtmr1),
            hex::encode(rtmr.rtmr2),
            hex::encode(rtmr.rtmr3)
        );

        let _ = fs::write("./test_data/rebuild_rtmr_output.txt", output);
    }

    #[test]
    fn test_query_digest() {
        let ccel_bin = fs::read("./test_data/CCEL_data").unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();

        let kernel_hash = ccel.query_digest(MeasuredEntity::TdShimKernel);
        let kernel_params_hash = ccel.query_digest(MeasuredEntity::TdShimKernelParams);

        assert!(kernel_hash.is_some());
        assert!(kernel_params_hash.is_some());

        assert_eq!(
            kernel_hash.unwrap(),
            "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa".to_string()
        );
        assert_eq!(
            kernel_params_hash.unwrap(),
            "64ed1e5a47e8632f80faf428465bd987af3e8e4ceb10a5a9f387b6302e30f4993bded2331f0691c4a38ad34e4cbbc627".to_string()
        );
    }
}
