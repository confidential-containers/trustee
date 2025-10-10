// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//
// This implementation is based on SPDM 1.1.1
// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf

use anyhow::{bail, Result};
use std::{fmt, mem::size_of};

use super::SPDM_VERSION_SUPPORTED;
use crate::nvidia::SPDM_NONCE_SIZE;

pub const SPDM_GET_MEASUREMENT_REQUEST_SIZE: usize = size_of::<SpdmGetMeasurementRequest>();

#[derive(Default, Debug)]
pub struct SpdmGetMeasurementRequest {
    pub spdm_version: u8,
    pub request_response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub nonce: [u8; SPDM_NONCE_SIZE],
    pub slot_id_param: u8,
}

impl fmt::Display for SpdmGetMeasurementRequest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "=== SPDM GetMesurements Request ===")?;
        writeln!(f, "spdm_version: {:#02x}", &self.spdm_version)?;
        writeln!(
            f,
            "request_response_code: {:#02x}",
            &self.request_response_code
        )?;
        writeln!(f, "param1: {:#02x}", &self.param1)?;
        writeln!(f, "param2: {:#02x}", &self.param2)?;
        writeln!(f, "nonce: {}", hex::encode(self.nonce))?;
        write!(f, "slot_id_param: {:#02x}", &self.slot_id_param)
    }
}

impl SpdmGetMeasurementRequest {
    /// Expected format for the GetMeasurements request message as in the DMTF's SPDM 1.1 spec:
    ///
    ///    OFFSET   - FIELD                   - SIZE(in bytes)
    ///    0        - SPDMVersion             - 1
    ///    1        - RequestResponseCode     - 1
    ///    2        - Param1                  - 1
    ///    3        - Param2                  - 1
    ///    4        - Nonce                   - 32
    ///    36       - SlotIDParam             - 1
    pub fn decode(bytes: &[u8]) -> Result<(Self, usize)> {
        // Check input mininum size
        if bytes.len() < SPDM_GET_MEASUREMENT_REQUEST_SIZE {
            bail!("SpdmGetMeasurmentRequest message is too small");
        }
        // Check SPDM version supported
        if bytes[0] != SPDM_VERSION_SUPPORTED {
            bail!("SPDM version {:#02x} not supported", &bytes[0]);
        }

        let mut request = Self {
            spdm_version: bytes[0],
            request_response_code: bytes[1],
            param1: bytes[2],
            param2: bytes[3],
            ..Default::default()
        };

        request.nonce.copy_from_slice(&bytes[4..36]);
        request.slot_id_param = bytes[36];

        Ok((request, SPDM_GET_MEASUREMENT_REQUEST_SIZE))
    }
}
