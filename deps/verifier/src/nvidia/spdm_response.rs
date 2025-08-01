// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

/// This implementation is based on SPDM 1.1.1
/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf

use std::{collections::HashMap, fmt, usize};

use anyhow::{anyhow, bail, Result};

use serde::Serialize;
use serde_json::Value;

use super::DMTF_MEASUREMENT_SPECIFICATION_VALUE;
use super::SPDM_VERSION_SUPPORTED;

// Simple u24 representation but save it in memory as usize
#[allow(non_camel_case_types)]
pub struct u24(usize);

impl u24 {
    pub fn from_le_bytes(bytes: [u8; 3]) -> Self {
        let num: usize = 
            usize::from(bytes[0]) |
            (usize::from(bytes[1]) << 8) |
            (usize::from(bytes[2]) << 16);
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
    pub nonce: [u8; 32],
    pub opaque_data_length: usize,
    pub opaque_data: HashMap<String, Value>,
    pub signature: Vec<u8>,
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
    pub fn decode(bytes: &[u8], signature_length: &usize) -> Result<Self> {
        // Check overflow for all fields up to offset 8 (MeasurementsRecordLength)
        if bytes.len() < 8 {
            bail!("SpdmGetMeasurementsResponse message smaller 8 bytes");
        }
        // Check SPDM version supported
        if bytes[0] != SPDM_VERSION_SUPPORTED {
            bail!("SPDM version {:#02x} not supported", &bytes[0]);
        }

        let mut response = SpdmGetMeasurementsResponse::default();

        response.spdm_version = bytes[0];
        response.request_response_code = bytes[1];
        response.param1 = bytes[2];
        response.param2 = bytes[3];
        response.number_of_blocks = usize::from(bytes[4]);

        // MeasurementRecordLength
        let array: [u8; 3] = bytes[5..8].try_into().unwrap();
        response.measurement_record_length = u24::from_le_bytes(array).as_usize();

        let mut offset: usize = 8;

        // MeasurementRecord
        if response.measurement_record_length > 0 {
            let measurements_bytes = bytes
                .get(offset..offset+response.measurement_record_length)
                .ok_or(anyhow!("MeasurementRecord overflow"))?;
            offset += response.measurement_record_length;
            response
                .measurement_record
                .extend_from_slice(
                    MeasurementRecord::decode(response.number_of_blocks, measurements_bytes)?
                        .as_slice()
                )
        }
 
        // Nonce
        let nonce = bytes
            .get(offset..offset+32)
            .ok_or(anyhow!("Nonce overflow"))?;
        response.nonce.copy_from_slice(nonce);
        offset += 32;

        // OpaqueDataLength
        let array: [u8; 2] = bytes
            .get(offset..offset+2)
            .ok_or(anyhow!("OpaqueDataLength overlow"))?
            .try_into()
            .unwrap();
        response.opaque_data_length = u16::from_le_bytes(array) as usize;
        offset += 2;

        // OpaqueData
        if response.opaque_data_length > 0 {
            let opaque_data_bytes = bytes
                .get(offset..offset+response.opaque_data_length)
                .ok_or(anyhow!("OpaqueData overflow"))?;
            offset += response.opaque_data_length;
            response.opaque_data = OpaqueData::decode(opaque_data_bytes)?;
        };

        // Signature
        let signature = bytes
            .get(offset..offset+signature_length)
            .ok_or(anyhow!("Signature overflow"))?;
        response.signature.extend_from_slice(signature);

        Ok(response)
    }
}

#[derive(Debug, Default)]
struct OpaqueData {}

impl OpaqueData {
    fn decode_switch_pdi(bytes: &[u8]) -> Result<Value> {
        const PDI_DATA_SIZE: usize = 8;

        if bytes.len() % PDI_DATA_SIZE != 0 {
            bail!("OpaqueDataType is not multiple of {}", PDI_DATA_SIZE)
        }
        let mut values: Vec<Value> = Vec::new();
        for chunk in bytes.chunks(PDI_DATA_SIZE) {
            values.push(Value::String(hex::encode(chunk)));
        }
        Ok(Value::Array(values))
    }

    fn decode_measurement_count(bytes: &[u8]) -> Result<Value> {
        const MSR_COUNT_SIZE: usize = 4;

        if bytes.len() % MSR_COUNT_SIZE != 0 {
            bail!("OpaqueDataType is not multiple of {}", MSR_COUNT_SIZE)
        }
        let mut values: Vec<Value> = Vec::new();
        for chunk in bytes.chunks(MSR_COUNT_SIZE) {
            let array: [u8; MSR_COUNT_SIZE] = chunk.try_into().unwrap();
            let num: u32 = u32::from_le_bytes(array);
            values.push(Value::Number(num.into()));
        }

        Ok(Value::Array(values))
    }

    /// OpaqueData field in the SPDM GET_MEASUREMENT response message, which is a free-form field if present
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
            // DataType
            let array: [u8; 2] = bytes[offset..offset+2].try_into().unwrap();
            let data_type = u16::from_le_bytes(array);
            offset += 2;

            let data_type = OpaqueDataType::from_u16(data_type)
                .ok_or(anyhow!("Invalid OpaqueDataType {}", data_type))?;

            // DataSize
            let array: [u8; 2] = bytes[offset..offset+2].try_into().unwrap();
            let data_size: usize = u16::from_le_bytes(array) as usize;
            offset += 2;

            // Data
            let data_bytes = bytes
                .get(offset..offset+data_size)
                .ok_or(anyhow!("OpaqueData overflow: offset {:#x}, data_size {:#x}", offset, data_size))?;
            offset += data_size;
         
            let value: Value = match data_type {
                // Driver Version
                OpaqueDataType::OPAQUE_FIELD_ID_DRIVER_VERSION |
                OpaqueDataType::OPAQUE_FIELD_ID_CHIP_SKU |
                OpaqueDataType::OPAQUE_FIELD_ID_CHIP_SKU_MOD |
                OpaqueDataType::OPAQUE_FIELD_ID_NVDEC0_STATUS |
                OpaqueDataType::OPAQUE_FIELD_ID_PROJECT |
                OpaqueDataType::OPAQUE_FIELD_ID_PROJECT_SKU |
                OpaqueDataType::OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS => Value::String(String::from_utf8_lossy(data_bytes).to_string()),
                // MeasureCount is a list of 4-bytes integers serialized in little-endian
                OpaqueDataType::OPAQUE_FIELD_ID_MSRSCNT => Self::decode_measurement_count(data_bytes)?,
                // SwitchPdi is a list of 8-bytes chunks
                OpaqueDataType::OPAQUE_FIELD_ID_SWITCH_PDI => Self::decode_switch_pdi(data_bytes)?,
                _ => Value::String(hex::encode(data_bytes)),
            };
            opaque_data.insert(data_type.to_string(), value);
        }

        Ok(opaque_data)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DmtfMeasurement {
    pub value_type: u8,
    pub value_size: usize,
    pub value: Vec<u8>,
}

impl DmtfMeasurement {
    /// The structure of the Measurement when MeasurementSpecification field is bit 0 = DMTF in DMTF's SPDM 1.1 spec.
    /// 
    /// OFFSET - FIELD                        - SIZE(in bytes)
    /// 0      - DMTFSpecMeasurementValueType - 1
    /// 1      - DMTFSpecMeasurementValueSize - 2
    /// 3      - DMTFSpecMeasurementValue     - DMTFSpecMeasurementValueSize
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 3 {
            bail!(anyhow!("DMTF measurement must be bigger than 3 bytes"));
        }
        let mut measurement = Self::default();

        measurement.value_type = bytes[0];

        let array: [u8; 2] = bytes[1..3].try_into().unwrap();
        measurement.value_size = u16::from_le_bytes(array) as usize;

        let value = bytes
            .get(3..3+measurement.value_size)
            .ok_or(anyhow!("DMTF measurement overflow"))?;
        measurement.value.extend_from_slice(value);

        Ok(measurement)
    }
}


struct MeasurementRecord {}

impl MeasurementRecord {
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

            let mut block = MeasurementBlock::default();

            // Index
            block.index = bytes[offset];
            offset += 1;

            // Measurement specification
            block.measurement_specification = bytes[offset];
            offset += 1;

            if block.measurement_specification != DMTF_MEASUREMENT_SPECIFICATION_VALUE {
                bail!("Only measurements encoded in the DMTF layout are supported");
            }
            
            // Measurement size
            let array: [u8; 2] = bytes[offset..offset+2].try_into().unwrap();
            block.measurement_size = u16::from_le_bytes(array) as usize;
            offset += 2;

            let measurement_data = bytes
                    .get(offset..offset+block.measurement_size)
                    .ok_or(anyhow!("Measurement overflow"))?;
            block.measurement = DmtfMeasurement::decode(measurement_data)?;
            offset += block.measurement_size;

            measurement_blocks.push(block);
        }

        Ok(measurement_blocks)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MeasurementBlock {
    pub index: u8,
    pub measurement_specification: u8,
    pub measurement_size: usize,
    pub measurement: DmtfMeasurement,
}
 
#[repr(u16)]
#[allow(non_camel_case_types)]
#[derive(Debug, Eq, Hash, PartialEq)]
enum OpaqueDataType {
        OPAQUE_FIELD_ID_CERT_ISSUER_NAME = 1,
        OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER = 2,
        OPAQUE_FIELD_ID_DRIVER_VERSION = 3,
        OPAQUE_FIELD_ID_GPU_INFO = 4,
        OPAQUE_FIELD_ID_SKU = 5,
        OPAQUE_FIELD_ID_VBIOS_VERSION = 6,
        OPAQUE_FIELD_ID_MANUFACTURER_ID = 7,
        OPAQUE_FIELD_ID_TAMPER_DETECTION = 8,
        OPAQUE_FIELD_ID_SMC = 9,
        OPAQUE_FIELD_ID_VPR = 10,
        OPAQUE_FIELD_ID_NVDEC0_STATUS = 11,
        OPAQUE_FIELD_ID_MSRSCNT = 12,
        OPAQUE_FIELD_ID_CPRINFO = 13,
        OPAQUE_FIELD_ID_BOARD_ID = 14,
        OPAQUE_FIELD_ID_CHIP_SKU = 15,
        OPAQUE_FIELD_ID_CHIP_SKU_MOD = 16,
        OPAQUE_FIELD_ID_PROJECT = 17,
        OPAQUE_FIELD_ID_PROJECT_SKU = 18,
        OPAQUE_FIELD_ID_PROJECT_SKU_MOD = 19,
        OPAQUE_FIELD_ID_FWID = 20,
        OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS = 21,
        OPAQUE_FIELD_ID_SWITCH_PDI = 22,
        OPAQUE_FIELD_ID_FLOORSWEPT_PORTS = 23,
        OPAQUE_FIELD_ID_POSITION_ID = 24,
        OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS = 25,
        OPAQUE_FIELD_ID_GPU_LINK_CONN = 32,
        OPAQUE_FIELD_ID_INVALID = 255,
}
impl OpaqueDataType {
    fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(OpaqueDataType::OPAQUE_FIELD_ID_CERT_ISSUER_NAME),
            2 => Some(OpaqueDataType::OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER),
            3 => Some(OpaqueDataType::OPAQUE_FIELD_ID_DRIVER_VERSION),
            4 => Some(OpaqueDataType::OPAQUE_FIELD_ID_GPU_INFO),
            5 => Some(OpaqueDataType::OPAQUE_FIELD_ID_SKU),
            6 => Some(OpaqueDataType::OPAQUE_FIELD_ID_VBIOS_VERSION),
            7 => Some(OpaqueDataType::OPAQUE_FIELD_ID_MANUFACTURER_ID),
            8 => Some(OpaqueDataType::OPAQUE_FIELD_ID_TAMPER_DETECTION),
            9 => Some(OpaqueDataType::OPAQUE_FIELD_ID_SMC),
            10 => Some(OpaqueDataType::OPAQUE_FIELD_ID_VPR),
            11 => Some(OpaqueDataType::OPAQUE_FIELD_ID_NVDEC0_STATUS),
            12 => Some(OpaqueDataType::OPAQUE_FIELD_ID_MSRSCNT),
            13 => Some(OpaqueDataType::OPAQUE_FIELD_ID_CPRINFO),
            14 => Some(OpaqueDataType::OPAQUE_FIELD_ID_BOARD_ID),
            15 => Some(OpaqueDataType::OPAQUE_FIELD_ID_CHIP_SKU),
            16 => Some(OpaqueDataType::OPAQUE_FIELD_ID_CHIP_SKU_MOD),
            17 => Some(OpaqueDataType::OPAQUE_FIELD_ID_PROJECT),
            18 => Some(OpaqueDataType::OPAQUE_FIELD_ID_PROJECT_SKU),
            19 => Some(OpaqueDataType::OPAQUE_FIELD_ID_PROJECT_SKU_MOD),
            20 => Some(OpaqueDataType::OPAQUE_FIELD_ID_FWID),
            21 => Some(OpaqueDataType::OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS),
            22 => Some(OpaqueDataType::OPAQUE_FIELD_ID_SWITCH_PDI),
            23 => Some(OpaqueDataType::OPAQUE_FIELD_ID_FLOORSWEPT_PORTS),
            24 => Some(OpaqueDataType::OPAQUE_FIELD_ID_POSITION_ID),
            25 => Some(OpaqueDataType::OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS),
            32 => Some(OpaqueDataType::OPAQUE_FIELD_ID_GPU_LINK_CONN),
            255 => Some(OpaqueDataType::OPAQUE_FIELD_ID_INVALID),
            _ => None,
        }
    }
}

impl fmt::Display for OpaqueDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            OpaqueDataType::OPAQUE_FIELD_ID_CERT_ISSUER_NAME => write!(f, "OPAQUE_FIELD_ID_CERT_ISSUER_NAME"),
            OpaqueDataType::OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER => write!(f, "OPAQUE_FIELD_ID_CERT_AUTHORITY_KEY_IDENTIFIER"),
            OpaqueDataType::OPAQUE_FIELD_ID_DRIVER_VERSION => write!(f, "OPAQUE_FIELD_ID_DRIVER_VERSION"),
            OpaqueDataType::OPAQUE_FIELD_ID_GPU_INFO => write!(f, "OPAQUE_FIELD_ID_GPU_INFO"),
            OpaqueDataType::OPAQUE_FIELD_ID_SKU => write!(f, "OPAQUE_FIELD_ID_SKU"),
            OpaqueDataType::OPAQUE_FIELD_ID_VBIOS_VERSION => write!(f, "OPAQUE_FIELD_ID_VBIOS_VERSION"),
            OpaqueDataType::OPAQUE_FIELD_ID_MANUFACTURER_ID => write!(f, "OPAQUE_FIELD_ID_MANUFACTURER_ID"),
            OpaqueDataType::OPAQUE_FIELD_ID_TAMPER_DETECTION => write!(f, "OPAQUE_FIELD_ID_TAMPER_DETECTION"),
            OpaqueDataType::OPAQUE_FIELD_ID_SMC => write!(f, "OPAQUE_FIELD_ID_SMC"),
            OpaqueDataType::OPAQUE_FIELD_ID_VPR => write!(f, "OPAQUE_FIELD_ID_VPR"),
            OpaqueDataType::OPAQUE_FIELD_ID_NVDEC0_STATUS => write!(f, "OPAQUE_FIELD_ID_NVDEC0_STATUS"),
            OpaqueDataType::OPAQUE_FIELD_ID_MSRSCNT => write!(f, "OPAQUE_FIELD_ID_MSRSCNT"),
            OpaqueDataType::OPAQUE_FIELD_ID_CPRINFO => write!(f, "OPAQUE_FIELD_ID_CPRINFO"),
            OpaqueDataType::OPAQUE_FIELD_ID_BOARD_ID => write!(f, "OPAQUE_FIELD_ID_BOARD_ID"),
            OpaqueDataType::OPAQUE_FIELD_ID_CHIP_SKU => write!(f, "OPAQUE_FIELD_ID_CHIP_SKU"),
            OpaqueDataType::OPAQUE_FIELD_ID_CHIP_SKU_MOD => write!(f, "OPAQUE_FIELD_ID_CHIP_SKU_MOD"),
            OpaqueDataType::OPAQUE_FIELD_ID_PROJECT => write!(f, "OPAQUE_FIELD_ID_PROJECT"),
            OpaqueDataType::OPAQUE_FIELD_ID_PROJECT_SKU => write!(f, "OPAQUE_FIELD_ID_PROJECT_SKU"),
            OpaqueDataType::OPAQUE_FIELD_ID_PROJECT_SKU_MOD => write!(f, "OPAQUE_FIELD_ID_PROJECT_SKU_MOD"),
            OpaqueDataType::OPAQUE_FIELD_ID_FWID => write!(f, "OPAQUE_FIELD_ID_FWID"),
            OpaqueDataType::OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS => write!(f, "OPAQUE_FIELD_ID_PROTECTED_PCIE_STATUS"),
            OpaqueDataType::OPAQUE_FIELD_ID_SWITCH_PDI => write!(f, "OPAQUE_FIELD_ID_SWITCH_PDI"),
            OpaqueDataType::OPAQUE_FIELD_ID_FLOORSWEPT_PORTS => write!(f, "OPAQUE_FIELD_ID_FLOORSWEPT_PORTS"),
            OpaqueDataType::OPAQUE_FIELD_ID_POSITION_ID => write!(f, "OPAQUE_FIELD_ID_POSITION_ID"),
            OpaqueDataType::OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS => write!(f, "OPAQUE_FIELD_ID_LOCK_SWITCH_STATUS"),
            OpaqueDataType::OPAQUE_FIELD_ID_GPU_LINK_CONN => write!(f, "OPAQUE_FIELD_ID_GPU_LINK_CONN"),
            OpaqueDataType::OPAQUE_FIELD_ID_INVALID => write!(f, "OPAQUE_FIELD_ID_INVALID"),
        }
    }
}