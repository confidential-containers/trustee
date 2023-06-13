// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! This module helps parse all fields inside a TDX Quote and CCEL and
//! serialize them into a JSON. The format will look lile
//! ```json
//! {
//!  "ccel": {
//!    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
//!    "kernel_parameters": {
//!      "console": "hvc0",
//!      "root": "/dev/vda1",
//!      "rw": null
//!    }
//!  },
//!  "quote": {
//!    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
//!    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
//!    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
//!    "seam_attributes": "0000000000000000",
//!    "td_attributes": "0100001000000000",
//!    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
//!    "tcb_svn": "03000500000000000000000000000000",
//!    "xfam": "e742060000000000"
//!  }
//!}
//! ```

use anyhow::*;
use as_types::TeeEvidenceParsedClaim;
use byteorder::{LittleEndian, ReadBytesExt};
use serde_json::{Map, Value};

use super::{
    eventlog::{CcEventLog, MeasuredEntity},
    quote::Quote,
};

macro_rules! parse_claim {
    ($map_name: ident, $key_name: literal, $field: ident) => {
        $map_name.insert($key_name.to_string(), serde_json::Value::Object($field))
    };
    ($map_name: ident, $key_name: literal, $field: expr) => {
        $map_name.insert(
            $key_name.to_string(),
            serde_json::Value::String(hex::encode($field)),
        )
    };
}

pub fn generate_parsed_claim(
    quote: Quote,
    cc_eventlog: Option<CcEventLog>,
) -> Result<TeeEvidenceParsedClaim> {
    let mut quote_map = Map::new();
    // Claims from TD Quote. We ignore RTMRs because when verifying the integrity of
    // the eventlog (CCEL), they have already been consumed.
    parse_claim!(quote_map, "tcb_svn", quote.report_body.tcb_svn);
    parse_claim!(quote_map, "mr_seam", quote.report_body.mr_seam);
    parse_claim!(quote_map, "mrsigner_seam", quote.report_body.mrsigner_seam);
    parse_claim!(
        quote_map,
        "seam_attributes",
        quote.report_body.seam_attributes
    );
    parse_claim!(quote_map, "td_attributes", quote.report_body.td_attributes);
    parse_claim!(quote_map, "xfam", quote.report_body.xfam);
    parse_claim!(quote_map, "mr_td", quote.report_body.mr_td);
    parse_claim!(quote_map, "mr_config_id", quote.report_body.mr_config_id);
    parse_claim!(quote_map, "mr_owner", quote.report_body.mr_owner);
    parse_claim!(
        quote_map,
        "mr_owner_config",
        quote.report_body.mr_owner_config
    );
    parse_claim!(quote_map, "report_data", quote.report_body.report_data);

    // Claims from CC EventLog.
    let mut ccel_map = Map::new();
    if let Some(ccel) = cc_eventlog {
        parse_ccel(ccel, &mut ccel_map)?;
    } else {
        warn!("parse CC EventLog: CCEL is null");
    }

    let mut claims = Map::new();
    parse_claim!(claims, "quote", quote_map);
    parse_claim!(claims, "ccel", ccel_map);
    log::info!("\nParsed Evidence claims map: \n{:?}\n", &claims);

    Ok(Value::Object(claims) as TeeEvidenceParsedClaim)
}

fn parse_ccel(ccel: CcEventLog, ccel_map: &mut Map<String, Value>) -> Result<()> {
    // Digest of kernel using td-shim
    match ccel.query_digest(MeasuredEntity::TdShimKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No td-shim kernel hash in CCEL");
        }
    }

    // Digest of kernel using TDVF
    match ccel.query_digest(MeasuredEntity::TdvfKernel) {
        Some(kernel_digest) => {
            ccel_map.insert(
                "kernel".to_string(),
                serde_json::Value::String(kernel_digest),
            );
        }
        _ => {
            warn!("No tdvf kernel hash in CCEL");
        }
    }

    // Map of Kernel Parameters
    match ccel.query_event_data(MeasuredEntity::TdShimKernelParams) {
        Some(config_info) => {
            let td_shim_platform_config_info =
                TdShimPlatformConfigInfo::try_from(&config_info[..])?;

            let parameters = parse_kernel_parameters(td_shim_platform_config_info.data)?;
            ccel_map.insert(
                "kernel_parameters".to_string(),
                serde_json::Value::Object(parameters),
            );
        }
        _ => {
            warn!("No kernel parameters in CCEL");
        }
    }

    Ok(())
}

/// Kernel Commandline Event inside Eventlog
pub struct TdShimPlatformConfigInfo<'a> {
    pub descriptor: [u8; 16],
    pub info_length: u32,
    pub data: &'a [u8],
}

impl<'a> TryFrom<&'a [u8]> for TdShimPlatformConfigInfo<'a> {
    type Error = anyhow::Error;

    fn try_from(data: &'a [u8]) -> std::result::Result<Self, Self::Error> {
        if data.len() < core::mem::size_of::<[u8; 16]>() + core::mem::size_of::<u32>() {
            bail!("give data slice is too short");
        }

        let descriptor = data[0..core::mem::size_of::<[u8; 16]>()].try_into()?;
        let info_length = (&data[core::mem::size_of::<[u8; 16]>()
            ..core::mem::size_of::<[u8; 16]>() + core::mem::size_of::<u32>()])
            .read_u32::<LittleEndian>()?;
        let data = &data[core::mem::size_of::<[u8; 16]>() + core::mem::size_of::<u32>()
            ..core::mem::size_of::<[u8; 16]>()
                + core::mem::size_of::<u32>()
                + info_length as usize];
        Ok(Self {
            descriptor,
            info_length,
            data,
        })
    }
}

fn parse_kernel_parameters(kernel_parameters: &[u8]) -> Result<Map<String, Value>> {
    let parameters_str = String::from_utf8(kernel_parameters.to_vec())?;
    debug!("kernel parameters: {parameters_str}");

    let parameters = parameters_str
        .split(&[' ', '\n', '\r', '\0'])
        .collect::<Vec<&str>>()
        .iter()
        .filter_map(|item| {
            if item.is_empty() {
                return None;
            }
            let it: Vec<&str> = item.split('=').collect();
            match it.len() {
                1 => Some((it[0].to_owned(), Value::Null)),
                2 => Some((it[0].to_owned(), Value::String(it[1].to_owned()))),
                _ => {
                    warn!("Illegal parameter: {item}");
                    None
                }
            }
        })
        .collect();

    Ok(parameters)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use serde_json::json;

    use crate::verifier::tdx::{eventlog::CcEventLog, quote::parse_tdx_quote};

    use super::generate_parsed_claim;

    #[test]
    fn parse_tdx_claims() {
        let quote_bin = std::fs::read("../test_data/tdx_quote_4.dat").expect("read quote failed");
        let ccel_bin = std::fs::read("../test_data/CCEL_data").expect("read ccel failed");
        let quote = parse_tdx_quote(&quote_bin).expect("parse quote");
        let ccel = CcEventLog::try_from(ccel_bin).expect("parse ccel");
        let claims = generate_parsed_claim(quote, Some(ccel)).expect("parse claim failed");
        let expected = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": null
                }
            },
            "quote": {
                "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "seam_attributes": "0000000000000000",
                "td_attributes": "0100001000000000",
                "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                "tcb_svn": "03000500000000000000000000000000",
                "xfam": "e742060000000000"
            }
        });

        assert_json_eq!(expected, claims);
    }
}
