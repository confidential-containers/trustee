use anyhow::*;
use byteorder::{LittleEndian, ReadBytesExt};
use cc_measurement::{log::CcEvents, TPML_ALG_SHA384};
use core::fmt;
use core::mem::size_of;
use sha2::{Digest, Sha384};
use std::convert::{TryFrom, TryInto};
use std::string::ToString;

/// Consist with https://github.com/confidential-containers/td-shim/blob/main/td-shim/src/event_log.rs
#[derive(Debug, Clone, EnumString, Display)]
pub enum MeasuredEntity {
    #[strum(serialize = "td_hob\0")]
    TdHob,
    #[strum(serialize = "td_payload\0")]
    TdPayload,
    #[strum(serialize = "td_payload_info\0")]
    TdPayloadInfo,
    // From here down is not supported
    #[strum(serialize = "td_payload_svn\0")]
    TdPayloadSVN,
    #[strum(serialize = "secure_policy_db")]
    SecurePolicyDB,
    #[strum(serialize = "secure_authority")]
    SecureAuthority,
}

#[derive(Debug, Clone, Copy)]
pub struct Rtmr {
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
}

#[derive(Clone)]
pub struct CcEventLog<'a> {
    pub cc_events: CcEvents<'a>,
}

impl<'a> fmt::Display for CcEventLog<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut parsed_ccel = String::default();
        for (header, data) in self.cc_events {
            parsed_ccel = format!(
                "{}\n{}\nEvent Data:\n\t{}\n",
                parsed_ccel,
                header,
                hex::encode(data)
            );
        }

        write!(f, "{parsed_ccel}")
    }
}

impl<'a> CcEventLog<'a> {
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
        let mut rtmr0: [u8; 96] = [0; 96];
        let mut rtmr1: [u8; 96] = [0; 96];
        let mut rtmr2: [u8; 96] = [0; 96];
        let mut rtmr3: [u8; 96] = [0; 96];

        for (event_header, _) in self.cc_events {
            let rtmr_index = match event_header.mr_index {
                0 => 0xFF,
                1 | 2 | 3 | 4 => event_header.mr_index - 1,
                e => {
                    ::log::info!("invalid pcr_index 0x{:x}\n", e);
                    0xFF
                }
            };
            if rtmr_index == 0 {
                rtmr0[48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
                let mut hasher = Sha384::new();
                hasher.update(rtmr0);
                let hash_value = hasher.finalize();
                rtmr0[0..48].copy_from_slice(hash_value.as_ref());
            } else if rtmr_index == 1 {
                rtmr1[48..].copy_from_slice(&event_header.digest.digests[0].digest.sha384);
                let mut hasher = Sha384::new();
                hasher.update(rtmr1);
                let hash_value = hasher.finalize();
                rtmr1[0..48].copy_from_slice(hash_value.as_ref());
            } else if rtmr_index == 2 {
                let mut hasher = Sha384::new();
                hasher.update(rtmr2);
                let hash_value = hasher.finalize();
                rtmr2[0..48].copy_from_slice(hash_value.as_ref());
            } else if rtmr_index == 3 {
                let mut hasher = Sha384::new();
                hasher.update(rtmr3);
                let hash_value = hasher.finalize();
                rtmr3[0..48].copy_from_slice(hash_value.as_ref());
            }
        }

        let mr = Rtmr {
            rtmr0: rtmr0[0..48].try_into()?,
            rtmr1: rtmr1[0..48].try_into()?,
            rtmr2: rtmr2[0..48].try_into()?,
            rtmr3: rtmr3[0..48].try_into()?,
        };

        Ok(mr)
    }

    pub fn query_digest(&self, entity: MeasuredEntity) -> Option<String> {
        let event_desc_prefix = Self::generate_query_key_prefix(entity)?;

        for (header, data) in self.cc_events {
            if data.len() < event_desc_prefix.len() {
                continue;
            }
            if &data[..event_desc_prefix.len()] == event_desc_prefix.as_slice() {
                let digest = &header.digest.digests[0];
                if digest.hash_alg == TPML_ALG_SHA384 {
                    let sha384 = digest.digest.sha384;
                    return Some(hex::encode(sha384));
                }
            }
        }
        None
    }

    #[allow(dead_code)]
    pub fn query_event_data(&self, entity: MeasuredEntity) -> Option<Vec<u8>> {
        let event_desc_prefix = Self::generate_query_key_prefix(entity)?;

        for (_, data) in self.cc_events {
            if data.len() < event_desc_prefix.len() {
                continue;
            }
            if &data[..event_desc_prefix.len()] == event_desc_prefix.as_slice() {
                return Some(data.to_vec());
            }
        }
        None
    }

    #[allow(unused_assignments)]
    fn generate_query_key_prefix(entity: MeasuredEntity) -> Option<Vec<u8>> {
        let mut event_desc_prefix = Vec::new();
        match entity {
            MeasuredEntity::TdPayload => {
                // Event data is in UEFI_PLATFORM_FIRMWARE_BLOB2 format
                // Defined in TCG PC Client Platform Firmware Profile Specification section
                // 'UEFI_PLATFORM_FIRMWARE_BLOB Structure Definition'
                let entity_name = entity.to_string();
                event_desc_prefix = vec![entity_name.as_bytes().len() as u8];
                event_desc_prefix.extend_from_slice(entity_name.as_bytes());
            }
            MeasuredEntity::TdHob | MeasuredEntity::TdPayloadInfo => {
                // Event data is in TD_SHIM_PLATFORM_CONFIG_INFO format
                // Defined in td-shim spec 'Table 3.5-4 TD_SHIM_PLATFORM_CONFIG_INFO'
                // link: https://github.com/confidential-containers/td-shim/blob/main/doc/tdshim_spec.md
                event_desc_prefix = entity.to_string().as_bytes().to_vec();
            }
            _ => {
                ::log::warn!("The Measured Entity is not supported by td-shim yet");
                return None;
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
    use cc_measurement::log::CcEventLogReader;
    use std::fs;

    #[test]
    fn test_parse_eventlog() {
        let ccel_bin = fs::read("test_data/CCEL_data").unwrap();
        let reader = CcEventLogReader::new(ccel_bin.as_slice()).unwrap();
        let ccel = CcEventLog {
            cc_events: reader.cc_events,
        };

        let _ = fs::write("test_data/parse_eventlog_output.txt", format!("{}", &ccel));
    }

    #[test]
    fn test_rebuild_rtmr() {
        let ccel_bin = fs::read("test_data/CCEL_data").unwrap();
        let reader = CcEventLogReader::new(ccel_bin.as_slice()).unwrap();
        let ccel = CcEventLog {
            cc_events: reader.cc_events,
        };

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

        let _ = fs::write("test_data/rebuild_rtmr_output.txt", output);
    }

    #[test]
    fn test_query_digest() {
        let ccel_bin = fs::read("test_data/CCEL_data").unwrap();
        let reader = CcEventLogReader::new(ccel_bin.as_slice()).unwrap();
        let ccel = CcEventLog {
            cc_events: reader.cc_events,
        };

        let kernel_hash = ccel.query_digest(MeasuredEntity::TdPayload);
        let kernel_params_hash = ccel.query_digest(MeasuredEntity::TdPayloadInfo);

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
