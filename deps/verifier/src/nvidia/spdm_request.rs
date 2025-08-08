// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

/// This implementation is based on SPDM 1.1.1
/// https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.1.1.pdf

use anyhow::{bail, Result};
use std::mem::size_of;

use super::SPDM_VERSION_SUPPORTED;

pub const SPDM_GET_MEASUREMENT_REQUEST_SIZE: usize = size_of::<SpdmGetMeasurementRequest>();

#[derive(Default, Debug)]
pub struct SpdmGetMeasurementRequest {
    pub spdm_version: u8,
    pub request_response_code: u8,
    pub param1: u8,
    pub param2: u8,
    pub nonce: [u8; 32],
    pub slot_id_param: u8,
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
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        // Check input mininum size
        if bytes.len() < SPDM_GET_MEASUREMENT_REQUEST_SIZE {
            bail!("SpdmGetMeasurmentRequest message is too small");
        }
       // Check SPDM version supported
        if bytes[0] != SPDM_VERSION_SUPPORTED {
            bail!("SPDM version {:#02x} not supported", &bytes[0]);
        }

        let mut request = SpdmGetMeasurementRequest::default();

        request.spdm_version = bytes[0];
        request.request_response_code = bytes[1];
        request.param1 = bytes[2];
        request.param2 = bytes[3];
        request.nonce.copy_from_slice(&bytes[4..36]);
        request.slot_id_param = bytes[36];

        Ok(request)
    }
}