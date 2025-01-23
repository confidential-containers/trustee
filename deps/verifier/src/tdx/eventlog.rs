use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use core::mem::size_of;
use eventlog_rs::Eventlog;
use log::{trace, warn};
use std::result::Result::Ok;
use strum::{AsRefStr, Display, EnumString};

const KERNEL_VENMEDIA_DEVPATH_OFFSET: usize = 55;

#[derive(AsRefStr, Copy, Debug, Clone, EnumString, Display)]
pub enum MeasuredEntity {
    #[strum(serialize = "td_hob\0")]
    TdShim,
    #[strum(serialize = "td_payload\0")]
    TdShimKernel,
    #[strum(serialize = "td_payload_info\0")]
    TdShimKernelParams,
    #[strum(serialize = "kernel")]
    TdvfKernel,
    #[strum(serialize = "LOADED_IMAGE::LoadOptions")]
    TdvfKernelParams,
    #[strum(serialize = "Linux initrd")]
    TdvfInitrd,
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

fn read_string(raw_bytes: &[u8]) -> Result<String, std::string::FromUtf16Error> {
    let utf16_string: Vec<u16> = raw_bytes
        .chunks_exact(2)
        .map(|c| u16::from_be_bytes(c.try_into().unwrap_or([0u8; 2])))
        .collect();

    String::from_utf16(utf16_string.as_ref())
}

impl CcEventLog {
    pub fn integrity_check(&self, rtmr_from_quote: Rtmr) -> Result<()> {
        let rtmr_eventlog = self.rebuild_rtmr()?;

        // Compare rtmr values from tdquote and EventLog acpi table
        if rtmr_from_quote.rtmr0 != rtmr_eventlog.rtmr0
            || rtmr_from_quote.rtmr1 != rtmr_eventlog.rtmr1
            || rtmr_from_quote.rtmr2 != rtmr_eventlog.rtmr2
        {
            bail!("RTMR 0, 1, 2 values from TD quote is not equal with the values from EventLog");
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
        for event_entry in self.cc_events.log.clone() {
            match (entity, event_entry.event_type.as_str()) {
                (MeasuredEntity::TdvfKernel, "EV_EFI_BOOT_SERVICES_APPLICATION") => {
                    let raw_bytes = &event_entry.event_desc[KERNEL_VENMEDIA_DEVPATH_OFFSET
                        ..KERNEL_VENMEDIA_DEVPATH_OFFSET + 2 * entity.as_ref().len()];

                    match read_string(raw_bytes) {
                        Ok(kernel) => {
                            if kernel == entity.as_ref() {
                                return event_entry.digests.first().map(|d| hex::encode(&d.digest));
                            }
                            warn!("Unknown Vendor Media Device Path: {kernel}");
                        }
                        Err(e) => warn!("Failed to read UEFI_IMAGE_LOAD_EVENT: {e}"),
                    }
                }
                (MeasuredEntity::TdvfKernelParams | MeasuredEntity::TdvfInitrd, "EV_EVENT_TAG") => {
                    let offset = size_of::<u32>();

                    // Read the tagged event size after the first u32 (=Event ID)
                    let event_size = (&event_entry.event_desc[offset..2 * offset])
                        .read_u32::<LittleEndian>()
                        .unwrap_or_default() as usize;

                    // Read the tagged event after the event size
                    match String::from_utf8(
                        event_entry.event_desc[offset * 2..offset * 2 + event_size - 1].to_vec(),
                    ) {
                        Ok(event) => {
                            if event == entity.as_ref() {
                                return event_entry.digests.first().map(|d| hex::encode(&d.digest));
                            }
                            warn!("Event {event:?} did not match with MeasuredEntity {entity:?}");
                        }

                        Err(e) => warn!("Failed to parse tagged event: {e}"),
                    }
                }
                (
                    MeasuredEntity::TdShim
                    | MeasuredEntity::TdShimKernel
                    | MeasuredEntity::TdShimKernelParams,
                    _,
                ) => {
                    let event_desc_prefix =
                        Self::generate_query_key_prefix(entity).unwrap_or_default();

                    if event_entry.event_desc.len() < event_desc_prefix.len() {
                        continue;
                    }
                    if &event_entry.event_desc[..event_desc_prefix.len()]
                        == event_desc_prefix.as_slice()
                    {
                        return event_entry.digests.first().map(|d| hex::encode(&d.digest));
                    }
                }
                (me, ev) => trace!("Event {ev:?} did not match with MeasuredEntity {me:?}"),
            }
        }
        None
    }

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

    fn generate_query_key_prefix(entity: MeasuredEntity) -> Option<Vec<u8>> {
        match entity {
            MeasuredEntity::TdShimKernel => {
                // Event data is in UEFI_PLATFORM_FIRMWARE_BLOB2 format
                // Defined in TCG PC Client Platform Firmware Profile Specification section
                // 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
                let entity_name = entity.to_string();
                let mut event_desc_prefix = vec![entity_name.len() as u8];
                event_desc_prefix.extend_from_slice(entity_name.as_bytes());
                Some(event_desc_prefix)
            }
            MeasuredEntity::TdShim | MeasuredEntity::TdShimKernelParams => {
                // Event data is in TD_SHIM_PLATFORM_CONFIG_INFO format
                // Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
                // link: https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md
                Some(entity.to_string().as_bytes().to_vec())
            }
            _ => None,
        }
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
