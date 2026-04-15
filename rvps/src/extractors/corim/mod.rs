// Copyright (c) 2026 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

//! CoRIM Extractor
//!
//! This extractor parses Concise Reference Integrity Manifests (CoRIM)
//! and extracts reference values from embedded CoMID tags.

use anyhow::{Context, Result};
use base64::Engine;
use corim_rs::{
    ConciseMidTag, ConciseTagTypeChoice, Corim, ExtensionValue, MeasuredElementTypeChoice,
    RawValueTypeChoice,
};
use tracing::debug;

use crate::ReferenceValue;

use super::Extractor;

#[derive(Default)]
pub struct CorimExtractor;

fn extract_rvs_from_comid(comid: &ConciseMidTag) -> Result<Vec<ReferenceValue>> {
    let mut rvs = vec![];
    let triples = &comid.triples;

    if let Some(ref_triples) = &triples.reference_triples {
        for triple in ref_triples {
            // Since CoRIMs can contain lots of different identifiers,
            // collect whatever identifiers we find in a vec.
            // We will join these all together to make the rv path.
            // For now, ignore the instance and group maps.
            let mut base_rv_path_components = vec![];

            // Collect environment information if it exists.
            let env = &triple.ref_env;

            if let Some(class) = &env.class {
                // Only add stringlike fields to the path for now.
                if let Some(v) = &class.vendor {
                    base_rv_path_components.push(v.to_string())
                }

                if let Some(m) = &class.model {
                    base_rv_path_components.push(m.to_string())
                }
            }

            for claim in &triple.ref_claims {
                let mut claim_rv_path_components = base_rv_path_components.clone();

                if let Some(key) = &claim.mkey {
                    match key {
                        MeasuredElementTypeChoice::Tstr(val) => {
                            claim_rv_path_components.push(val.to_string())
                        }
                        MeasuredElementTypeChoice::UInt(val) => {
                            claim_rv_path_components.push(format!("claim{val}"))
                        }
                        MeasuredElementTypeChoice::Uuid(val) => {
                            let uuid = &val.0 .0.as_slice();
                            let uuid = uuid::Uuid::from_slice(uuid)?.to_string();
                            claim_rv_path_components.push(uuid);
                        }
                        _ => (), // todo: support other key types
                    }
                }

                // todo: add non-string types
                if let Some(n) = &claim.mval.name {
                    claim_rv_path_components.push(n.to_string())
                }

                if let Some(s) = &claim.mval.serial_number {
                    claim_rv_path_components.push(s.to_string())
                }

                // todo: support registers
                if let Some(digests) = &claim.mval.digests {
                    let mut rv_digests = vec![];
                    let mut digest_rv_path_components = claim_rv_path_components.clone();
                    digest_rv_path_components.push("digests".to_string());

                    for digest in digests {
                        let hash_bytes = digest.val.as_ref();
                        let hash_hex = hex::encode(hash_bytes);
                        rv_digests.push(hash_hex);
                    }

                    let name = digest_rv_path_components.join("/");
                    let rv = ReferenceValue::new()?
                        .set_name(&name)
                        .set_value(serde_json::to_value(&rv_digests)?);

                    rvs.push(rv);
                }

                if let Some(raw_value) = &claim.mval.raw {
                    let mut raw_rv_path_components = claim_rv_path_components.clone();

                    if let RawValueTypeChoice::TaggedBytes(bytes) = &raw_value.raw_value {
                        raw_rv_path_components.push("raw_bytes".to_string());

                        let hex = hex::encode(bytes.as_slice());

                        let name = raw_rv_path_components.join("/");
                        let rv = ReferenceValue::new()?
                            .set_name(&name)
                            .set_value(serde_json::to_value(hex)?);

                        rvs.push(rv);
                    }
                }
            }
        }
    }

    Ok(rvs)
}

// Some CoRIMs are wrapped with ASN Header tags..
// If we find CBOR tags 500 or 502 at the start of the CoRIM,
// remove them.
//
// Specifically, this might look like d901 f4d9 01f6
// where 0xd9 denotes a CBOR tag and 0x01f4 are 0x01f6
// the problematic tag numbers.
//
// Something similar has been done by cocli, see
// https://github.com/veraison/corim/pull/133
fn strip_outer_tags(data: &[u8]) -> &[u8] {
    let mut slice = data;
    loop {
        if slice.len() < 3 {
            break;
        }
        if slice[0] == 0xd9 {
            let tag = u16::from_be_bytes([slice[1], slice[2]]);
            if tag == 500 || tag == 502 {
                slice = &slice[3..];
                continue;
            }
        }
        break;
    }
    slice
}

impl Extractor for CorimExtractor {
    /// Extract reference values from CoRIMs.
    /// Note that this does not yet check the signature of signed CoRIMs.
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        let cbor_bytes = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("Failed to decode CoRIM as base64")?;

        let cbor_bytes = strip_outer_tags(&cbor_bytes);

        let corim = Corim::from_cbor(cbor_bytes)?;
        let corim_map = corim.as_map_ref();

        let mut rvs: Vec<ReferenceValue> = vec![];

        for tag in &corim_map.tags {
            match tag {
                ConciseTagTypeChoice::Mid(comid) => {
                    rvs.extend(extract_rvs_from_comid(comid.as_ref())?);
                }
                ConciseTagTypeChoice::Extension(ExtensionValue::Bytes(bytes)) => {
                    // Manually parse as CoMID
                    if let Ok(comid) = ciborium::from_reader::<ConciseMidTag, _>(bytes.as_ref()) {
                        rvs.extend(extract_rvs_from_comid(&comid)?);
                    }
                }
                _ => {
                    debug!("Skipping non-CoMID tag");
                }
            }
        }

        Ok(rvs)
    }
}

#[cfg(test)]
mod tests {
    use super::CorimExtractor;
    use crate::extractors::Extractor;
    use base64::Engine;

    #[test]
    fn extract_test_corim() {
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init()
            .ok();

        let cbor_bytes = include_bytes!("unsigned-example-corim.cbor");

        let b64 = base64::engine::general_purpose::STANDARD.encode(cbor_bytes);
        let extractor = CorimExtractor;
        let rvs = extractor.verify_and_extract(&b64).unwrap();

        assert!(rvs[2].name == "ACME/RoadRunner/31fb5abf-023e-4992-aa4e-95f9c1503bfa/digests");
        assert!(
            rvs[2].value[0] == "a3a5e715f0cc574a73c3f9bebb6bc24f32ffd5b67b387244c2c909da779a1478"
        );
    }
}
