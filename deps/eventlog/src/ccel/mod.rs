// Copyright (c) 2025 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::{ElDigest, EventDetails};
use anyhow::bail;
use sha2::{Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;

pub mod blank;
pub mod boot_services_app;
pub mod device_paths;
pub mod efi_variable;
pub mod event_tag;
pub mod ipl;
pub mod platform_config_flags;
pub mod simple;
pub mod simple_string;
pub mod tcg_enum;

use crate::ccel::tcg_enum::TcgAlgorithm;
pub(crate) use blank::EvBlankParser;
pub(crate) use boot_services_app::EvBootServicesAppParser;
pub(crate) use efi_variable::EvEfiVariableParser;
pub(crate) use event_tag::EvEventTagParser;
pub(crate) use ipl::EvIplParser;
pub(crate) use platform_config_flags::EvPlatformConfigFlagsParser;
pub(crate) use simple::EvSimpleParser;
pub(crate) use simple_string::SimpleStringParser;

/// All parser implementations follow structures defined in <https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub-3.pdf>
pub trait EventDataParser: Sync + Send {
    fn parse(&self, data: Vec<u8>) -> anyhow::Result<EventDetails>;

    fn compare_digests(&self, data: &Vec<u8>, digests: &Vec<ElDigest>) -> anyhow::Result<bool> {
        for digest in digests {
            let computed = match digest.alg {
                TcgAlgorithm::Sha256 => Sha256::digest(data).to_vec(),
                TcgAlgorithm::Sha384 => Sha384::digest(data).to_vec(),
                TcgAlgorithm::Sha512 => Sha512::digest(data).to_vec(),
                TcgAlgorithm::Sm3 => Sm3::digest(data).to_vec(),
                algorithm => bail!(
                    "Digest comparison failed: Digest hash algorithm not supported - {:?}",
                    algorithm
                ),
            };

            if computed != digest.digest {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
