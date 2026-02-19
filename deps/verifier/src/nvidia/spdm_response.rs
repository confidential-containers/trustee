// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// This implementation is based on SPDM 1.1.1
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf

use anyhow::{anyhow, bail, Result};
use serde_json::Map;
use serde_json::Value;
use std::{collections::HashMap, fmt};

use super::DMTF_MEASUREMENT_SPECIFICATION_VALUE;
use super::SPDM_VERSION_SUPPORTED;
use crate::nvidia::SPDM_NONCE_SIZE;

// Simple u24 representation but save it in memory as usize
#[allow(non_camel_case_types)]
pub struct u24(usize);

impl u24 {
    pub fn from_le_bytes(bytes: [u8; 3]) -> Self {
        let num: usize =
            usize::from(bytes[0]) | (usize::from(bytes[1]) << 8) | (usize::from(bytes[2]) << 16);
        u24(num)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }
}
#[derive(Debug, Default)]
pub struct SpdmGetMeasurementsResponse {
    pub spdm_version: u8,
    pub request_response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub number_of_blocks: usize,
    pub measurement_record_length: usize,
    pub measurement_record: Vec<MeasurementBlock>,
    pub nonce: [u8; SPDM_NONCE_SIZE],
    pub opaque_data_length: usize,
    pub opaque_data: HashMap<String, Value>,
    pub signature: Vec<u8>,
}

impl fmt::Display for SpdmGetMeasurementsResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "=== SPDM GetMesurements Response ===")?;
        writeln!(f, "spdm_version: {:#02x}", &self.spdm_version)?;
        writeln!(
            f,
            "request_response_code: {:#02x}",
            &self.request_response_code
        )?;
        writeln!(f, "param1: {:#02x}", &self.param1)?;
        writeln!(f, "param2: {:#02x}", &self.param2)?;
        writeln!(f, "number_of_blocks: {}", &self.number_of_blocks)?;
        writeln!(
            f,
            "measurement_record_length {}",
            &self.measurement_record_length
        )?;
        writeln!(f, "Measurement Record:")?;
        writeln!(f, "---------------")?;
        for block in &self.measurement_record {
            writeln!(f, "{}", &block)?;
            writeln!(f, "---------------")?;
        }
        writeln!(f, "nonce: {}", hex::encode(self.nonce))?;
        for (key, value) in &self.opaque_data {
            writeln!(f, "{}: {}", key, value)?;
        }
        write!(f, "signature: {}", hex::encode(&self.signature))
    }
}

impl SpdmGetMeasurementsResponse {
    /// Expected format for a Successful GetMeasurements response message
    ///
    /// OFFSET   - FIELD                   - SIZE(in bytes)
    /// 0        - SPDMVersion             - 1
    /// 1        - RequestResponseCode     - 1
    /// 2        - Param1                  - 1
    /// 3        - Param2                  - 1
    /// 4        - NumberOfBlocks          - 1
    /// 5        - MeasurementRecordLength - 3
    /// 8        - MeasurementRecord       - L1 = MeasurementRecordLength
    /// 8+L1     - Nonce                   - 32
    /// 40+L1    - OpaqueLength            - 2
    /// 42+L1    - OpaqueData              - L2 = OpaqueLength
    /// 42+L1+L2 - Signature               - 64
    pub fn decode(bytes: &[u8], signature_length: &usize) -> Result<(Self, usize)> {
        // Check overflow for all fields up to offset 8 (MeasurementsRecordLength)
        if bytes.len() < 8 {
            bail!("SpdmGetMeasurementsResponse message smaller 8 bytes");
        }
        // Check SPDM version supported
        if bytes[0] != SPDM_VERSION_SUPPORTED {
            bail!("SPDM version {:#02x} not supported", &bytes[0]);
        }

        let mut response = Self {
            spdm_version: bytes[0],
            request_response_code: bytes[1],
            param1: bytes[2],
            param2: bytes[3],
            number_of_blocks: usize::from(bytes[4]),
            ..Default::default()
        };

        // MeasurementRecordLength
        let array: [u8; 3] = bytes[5..8].try_into()?;
        response.measurement_record_length = u24::from_le_bytes(array).as_usize();

        let mut offset: usize = 8;

        // MeasurementRecord
        if response.measurement_record_length > 0 {
            let measurements_bytes = bytes
                .get(offset..offset + response.measurement_record_length)
                .ok_or(anyhow!("MeasurementRecord overflow"))?;
            offset += response.measurement_record_length;
            response.measurement_record.extend_from_slice(
                MeasurementRecord::decode(response.number_of_blocks, measurements_bytes)?
                    .as_slice(),
            )
        }

        // Nonce
        let nonce = bytes
            .get(offset..offset + 32)
            .ok_or(anyhow!("Nonce overflow"))?;
        response.nonce.copy_from_slice(nonce);
        offset += 32;

        // OpaqueDataLength
        let array: [u8; 2] = bytes
            .get(offset..offset + 2)
            .ok_or(anyhow!("OpaqueDataLength overlow"))?
            .try_into()?;
        response.opaque_data_length = u16::from_le_bytes(array) as usize;
        offset += 2;

        // OpaqueData
        if response.opaque_data_length > 0 {
            let opaque_data_bytes = bytes
                .get(offset..offset + response.opaque_data_length)
                .ok_or(anyhow!("OpaqueData overflow"))?;
            offset += response.opaque_data_length;
            response.opaque_data = OpaqueData::decode(opaque_data_bytes)?;
        };

        // Signature
        let signature = bytes
            .get(offset..offset + signature_length)
            .ok_or(anyhow!("Signature overflow"))?;
        response.signature.extend_from_slice(signature);
        offset += signature_length;

        Ok((response, offset))
    }
}

/// OpaqueData field in the SPDM GET_MEASUREMENT response message, which is a *free-form* field if present
#[derive(Debug, Default)]
struct OpaqueData;

/// NVIDIA is using the OpaqueData to carry OpaqueDataType values, as many as available for the device.
#[derive(Debug, Default)]
struct NvidiaOpaqueDataItem {
    r#type: OpaqueDataType,
    size: usize,
    data: Value,
}

impl OpaqueData {
    /// Decode the OpaqueData for Nvidia. We store the OpaqueDataItems
    /// in a hashmap, which is more convenient for generating device claims
    ///
    /// Layout for each OpaqueDataItem
    ///
    /// OFFSET   - FIELD                        - SIZE(in bytes)
    /// 0        - DataType                     - 2
    /// 2        - DataSize                     - 2
    /// 4        - Data                         - DataSize
    pub fn decode(bytes: &[u8]) -> Result<HashMap<String, Value>> {
        let bytes_len: usize = bytes.len();
        let mut opaque_data: HashMap<String, Value> = HashMap::new();

        if bytes_len == 0 {
            return Ok(opaque_data);
        }

        let mut offset: usize = 0;

        while offset + 4 < bytes_len {
            let mut item = NvidiaOpaqueDataItem::default();

            // DataType
            let array: [u8; 2] = bytes[offset..offset + 2].try_into()?;
            let data_type = u16::from_le_bytes(array);
            item.r#type = OpaqueDataType::from_u16(data_type)
                .ok_or(anyhow!("Invalid OpaqueDataType {}", data_type))?;
            offset += 2;

            // DataSize
            let array: [u8; 2] = bytes[offset..offset + 2].try_into()?;
            item.size = u16::from_le_bytes(array) as usize;
            offset += 2;

            // Data
            let data_bytes = bytes.get(offset..offset + item.size).ok_or(anyhow!(
                "OpaqueData overflow: offset {:#x}, data_size {:#x}",
                offset,
                item.size,
            ))?;
            offset += item.size;

            item.data = match item.r#type {
                OpaqueDataType::DriverVersion
                | OpaqueDataType::ChipSku
                | OpaqueDataType::ChipSkuMod
                | OpaqueDataType::Nvdec0Status
                | OpaqueDataType::Project
                | OpaqueDataType::ProjectSku
                | OpaqueDataType::ProtectedPcieStatus
                | OpaqueDataType::ChipInfo => Value::String(
                    String::from_utf8_lossy(data_bytes)
                        .trim_end_matches('\0')
                        .to_string(),
                ),
                OpaqueDataType::VbiosVersion => Value::String(
                    Self::format_vbios_version(data_bytes)
                        .ok_or(anyhow!("Invalid gpu vbios version"))?,
                ),
                OpaqueDataType::MsrsCnt => Self::decode_measurement_count(data_bytes)?,
                OpaqueDataType::SwitchPdi => Self::decode_switch_pdi(data_bytes)?,
                OpaqueDataType::OpaqueDataVersion => {
                    Value::Number(Self::decode_le_u64(data_bytes)?.into())
                }
                OpaqueDataType::FeatureFlag => Self::decode_feature_flag(data_bytes)?,
                OpaqueDataType::Invalid => bail!(anyhow!("Hashmap: Invalid OpaqueDataType")),
                _ => Value::String(hex::encode(data_bytes)),
            };

            let key = item.r#type.to_string();

            // Check if the key already exists
            if opaque_data.contains_key(&key) {
                bail!(anyhow!("Duplicated OpaqueDataType: {}", &key));
            }

            opaque_data.insert(key, item.data);
        }

        // Ensure that at least the vbios_version and driver_version are present in the
        // hashmap as they are important to determine the TCB of the device
        if !opaque_data.contains_key(&OpaqueDataType::VbiosVersion.to_string())
            || !opaque_data.contains_key(&OpaqueDataType::DriverVersion.to_string())
        {
            bail!(anyhow!(
                "Both vbios_version and driver_version must be present in the report"
            ));
        }

        Ok(opaque_data)
    }

    /// Format vbios version from bytes.
    /// - Take the first half from bytes, reverse and hex encode it.
    /// - Append first item of the second half
    ///
    /// E.g.:
    /// bytes = b'\x00\x9f\x00\x96\x01\x00\x00\x00'
    /// vbios version = 96.00.9f.00.01
    fn format_vbios_version(bytes: &[u8]) -> Option<String> {
        let mut version = bytes
            .get(..bytes.len() / 2)?
            .iter()
            .rev()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<String>>()
            .join(".");
        version = format!("{}.{:02x}", version, bytes.get(bytes.len() / 2)?,);

        Some(version)
    }

    /// Decode a list SwitchPdi values from bytes, which is a list of 8-bytes chunks
    fn decode_switch_pdi(bytes: &[u8]) -> Result<Value> {
        const PDI_DATA_SIZE: usize = 8;

        if !bytes.len().is_multiple_of(PDI_DATA_SIZE) {
            bail!("OpaqueDataType is not multiple of {}", PDI_DATA_SIZE)
        }
        let mut values: Vec<Value> = Vec::new();
        for chunk in bytes.chunks(PDI_DATA_SIZE) {
            values.push(Value::String(hex::encode(chunk)));
        }
        Ok(Value::Array(values))
    }

    /// Decode a list of MeasurementCount values from bytes, which is a list of
    /// 4-bytes integers serialized in little-endian.
    /// There is one measurement_count for each measurement in the MeasurementRecord.
    fn decode_measurement_count(bytes: &[u8]) -> Result<Value> {
        const MSR_COUNT_SIZE: usize = 4;

        if !bytes.len().is_multiple_of(MSR_COUNT_SIZE) {
            bail!("OpaqueDataType is not multiple of {}", MSR_COUNT_SIZE)
        }
        let mut values: Map<String, Value> = Map::new();
        let mut index: u8 = 1;
        for chunk in bytes.chunks(MSR_COUNT_SIZE) {
            let array: [u8; MSR_COUNT_SIZE] = chunk.try_into()?;
            let num: u32 = u32::from_le_bytes(array);
            values.insert(index.to_string(), Value::Number(num.into()));
            index += 1;
        }

        Ok(Value::Object(values))
    }

    fn decode_feature_flag(bytes: &[u8]) -> Result<Value> {
        let value = Self::decode_le_u64(bytes)?;
        let feature = match value {
            0 => "SPT",
            1 => "MPT",
            2 => "PPCIE",
            _ => "unknown",
        };
        Ok(Value::String(feature.to_string()))
    }

    fn decode_le_u64(bytes: &[u8]) -> Result<u64> {
        if bytes.len() > 8 {
            bail!("OpaqueDataType integer larger than 8 bytes");
        }
        let mut padded = [0u8; 8];
        let len = bytes.len().min(8);
        padded[..len].copy_from_slice(&bytes[..len]);

        let value = u64::from_le_bytes(padded);
        Ok(value)
    }
}

#[derive(Clone, Debug, Default)]
pub struct DmtfMeasurement {
    pub r#type: u8,
    pub size: usize,
    pub value: Vec<u8>,
}

impl fmt::Display for DmtfMeasurement {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "measurement_type: {}", &self.r#type)?;
        write!(f, "measurement_value: {}", hex::encode(&self.value))
    }
}

impl DmtfMeasurement {
    /// OFFSET - FIELD                        - SIZE(in bytes)
    /// 0      - DMTFSpecMeasurementValueType - 1
    /// 1      - DMTFSpecMeasurementValueSize - 2
    /// 3      - DMTFSpecMeasurementValue     - DMTFSpecMeasurementValueSize
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 {
            bail!(anyhow!("DMTF measurement must be bigger than 3 bytes"));
        }
        let mut measurement = Self {
            r#type: bytes[0],
            ..Default::default()
        };

        let array: [u8; 2] = bytes[1..3].try_into()?;
        measurement.size = u16::from_le_bytes(array) as usize;

        let value = bytes
            .get(3..3 + measurement.size)
            .ok_or(anyhow!("DMTF measurement overflow"))?;
        measurement.value.extend_from_slice(value);

        Ok(measurement)
    }
}

/// List of all MeasurementBlock as requested in the SPDM GET_MEASUREMENTS request
struct MeasurementRecord;

impl MeasurementRecord {
    /// Decode the list of MeasurementBlock
    ///
    /// Layout of each SPDM MeasurementBlock
    ///
    /// OFFSET   - FIELD                        - SIZE(in bytes)
    /// 0        - Index                        - 1
    /// 1        - MeasurementSpecification     - 1
    /// 2        - MeasurementSize              - 2
    /// 4        - Measurement                  - MeasurementSize
    pub fn decode(number_of_blocks: usize, bytes: &[u8]) -> Result<Vec<MeasurementBlock>> {
        let mut measurement_blocks: Vec<MeasurementBlock> = Vec::new();

        if number_of_blocks == 0 {
            return Ok(measurement_blocks);
        }

        let data_len = bytes.len();
        let mut offset: usize = 0;

        for _ in 0..number_of_blocks {
            if data_len < offset + 4 {
                bail!("MeasurementBlock overflow");
            }

            let mut block = MeasurementBlock {
                index: bytes[offset],
                measurement_specification: bytes[offset + 1],
                ..Default::default()
            };

            offset += 2;

            if block.measurement_specification != DMTF_MEASUREMENT_SPECIFICATION_VALUE {
                bail!("Only measurements encoded in the DMTF layout are supported");
            }

            // Measurement size
            let array: [u8; 2] = bytes[offset..offset + 2].try_into()?;
            block.measurement_size = u16::from_le_bytes(array) as usize;
            offset += 2;

            let measurement_data = bytes
                .get(offset..offset + block.measurement_size)
                .ok_or(anyhow!("Measurement overflow"))?;
            block.measurement = DmtfMeasurement::decode(measurement_data)?;
            offset += block.measurement_size;

            measurement_blocks.push(block);
        }

        Ok(measurement_blocks)
    }
}

/// Structure of each MeasurementBlock listed in the MeasurementRecord
#[derive(Clone, Debug, Default)]
pub struct MeasurementBlock {
    pub index: u8,
    /// Bit Mask. The value shall indicate the measurement specification that the requested
    /// measurement follows.
    ///
    /// Bit0 = DMTF
    ///
    /// All other bits are reserved
    pub measurement_specification: u8,
    pub measurement_size: usize,
    pub measurement: DmtfMeasurement,
}

impl fmt::Display for MeasurementBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "Measurement block index: {}", &self.index)?;
        write!(f, "{}", &self.measurement)
    }
}

#[repr(u16)]
#[derive(Debug, Default, Eq, Hash, PartialEq)]
pub enum OpaqueDataType {
    CertIssuerName = 1,
    CertAuthorityKeyIdentifier = 2,
    DriverVersion = 3,
    GpuInfo = 4,
    IdSku = 5,
    VbiosVersion = 6,
    ManufacturerId = 7,
    TamperDetection = 8,
    Smc = 9,
    Vpr = 10,
    Nvdec0Status = 11,
    MsrsCnt = 12,
    CprInfo = 13,
    BoardId = 14,
    ChipSku = 15,
    ChipSkuMod = 16,
    Project = 17,
    ProjectSku = 18,
    ProjectSkuMod = 19,
    Fwid = 20,
    ProtectedPcieStatus = 21,
    SwitchPdi = 22,
    FloorsweptPorts = 23,
    PositionId = 24,
    LockSwitchStatus = 25,
    GpuLinkConn = 32,
    SysEnableStatus = 33,
    OpaqueDataVersion = 34,
    ChipInfo = 35,
    FeatureFlag = 36,
    #[default]
    Invalid = 255,
}
impl OpaqueDataType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(OpaqueDataType::CertIssuerName),
            2 => Some(OpaqueDataType::CertAuthorityKeyIdentifier),
            3 => Some(OpaqueDataType::DriverVersion),
            4 => Some(OpaqueDataType::GpuInfo),
            5 => Some(OpaqueDataType::IdSku),
            6 => Some(OpaqueDataType::VbiosVersion),
            7 => Some(OpaqueDataType::ManufacturerId),
            8 => Some(OpaqueDataType::TamperDetection),
            9 => Some(OpaqueDataType::Smc),
            10 => Some(OpaqueDataType::Vpr),
            11 => Some(OpaqueDataType::Nvdec0Status),
            12 => Some(OpaqueDataType::MsrsCnt),
            13 => Some(OpaqueDataType::CprInfo),
            14 => Some(OpaqueDataType::BoardId),
            15 => Some(OpaqueDataType::ChipSku),
            16 => Some(OpaqueDataType::ChipSkuMod),
            17 => Some(OpaqueDataType::Project),
            18 => Some(OpaqueDataType::ProjectSku),
            19 => Some(OpaqueDataType::ProjectSkuMod),
            20 => Some(OpaqueDataType::Fwid),
            21 => Some(OpaqueDataType::ProtectedPcieStatus),
            22 => Some(OpaqueDataType::SwitchPdi),
            23 => Some(OpaqueDataType::FloorsweptPorts),
            24 => Some(OpaqueDataType::PositionId),
            25 => Some(OpaqueDataType::LockSwitchStatus),
            32 => Some(OpaqueDataType::GpuLinkConn),
            33 => Some(OpaqueDataType::SysEnableStatus),
            34 => Some(OpaqueDataType::OpaqueDataVersion),
            35 => Some(OpaqueDataType::ChipInfo),
            36 => Some(OpaqueDataType::FeatureFlag),
            _ => None,
        }
    }
}

impl fmt::Display for OpaqueDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Each data type name is renamed to match the name defined by NVIDIA in the nvtrust repository.
        match self {
            OpaqueDataType::CertIssuerName => write!(f, "cert_issuer_name"),
            OpaqueDataType::CertAuthorityKeyIdentifier => {
                write!(f, "cert_authority_key_identifier")
            }
            OpaqueDataType::DriverVersion => write!(f, "driver_version"),
            OpaqueDataType::GpuInfo => write!(f, "gpu_info"),
            OpaqueDataType::IdSku => write!(f, "id_sku"),
            OpaqueDataType::VbiosVersion => write!(f, "vbios_version"),
            OpaqueDataType::ManufacturerId => write!(f, "manufacturer_id"),
            OpaqueDataType::TamperDetection => write!(f, "tamper_detection"),
            OpaqueDataType::Smc => write!(f, "smc"),
            OpaqueDataType::Vpr => write!(f, "vpr"),
            OpaqueDataType::Nvdec0Status => write!(f, "nvdec0_status"),
            OpaqueDataType::MsrsCnt => write!(f, "measurement_count"),
            OpaqueDataType::CprInfo => write!(f, "cpr_info"),
            OpaqueDataType::BoardId => write!(f, "board_id"),
            OpaqueDataType::ChipSku => write!(f, "chip_sku"),
            OpaqueDataType::ChipSkuMod => write!(f, "chip_sku_mod"),
            OpaqueDataType::Project => write!(f, "project"),
            OpaqueDataType::ProjectSku => write!(f, "project_sku"),
            OpaqueDataType::ProjectSkuMod => write!(f, "project_sku_mod"),
            OpaqueDataType::Fwid => write!(f, "fwid"),
            OpaqueDataType::ProtectedPcieStatus => write!(f, "protected_pcie_status"),
            OpaqueDataType::SwitchPdi => write!(f, "switch_pdi"),
            OpaqueDataType::FloorsweptPorts => write!(f, "floorswept_ports"),
            OpaqueDataType::PositionId => write!(f, "position_id"),
            OpaqueDataType::LockSwitchStatus => write!(f, "lock_switch_status"),
            OpaqueDataType::GpuLinkConn => write!(f, "gpu_link_conn"),
            OpaqueDataType::SysEnableStatus => write!(f, "sys_enable_status"),
            OpaqueDataType::OpaqueDataVersion => write!(f, "opaque_data_version"),
            OpaqueDataType::ChipInfo => write!(f, "chip_info"),
            OpaqueDataType::FeatureFlag => write!(f, "feature_flag"),
            OpaqueDataType::Invalid => write!(f, "invalid"),
        }
    }
}
