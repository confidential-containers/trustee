// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use chrono::{Months, Timelike, Utc};
use log::{debug, info};

use crate::{
    reference_value::{HashValuePair, REFERENCE_VALUE_VERSION},
    ReferenceValue,
};

use super::Extractor;

#[derive(Default)]
pub struct SwidExtractor;

/// Default reference value hash algorithm
const DEFAULT_ALG: &str = "sha384";

/// The reference value will be expired in the default time (months)
const MONTHS_BEFORE_EXPIRATION: u32 = 12;

const SWID_NS: &str = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";
const RIMIM_NS: &str = "https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/";
const HASH_NS: &str = "http://www.w3.org/2001/04/xmlenc#sha384";

impl Extractor for SwidExtractor {
    fn verify_and_extract(&self, provenance_base64: &str) -> Result<Vec<ReferenceValue>> {
        info!("Extracting reference values from SWID/RIM manifest.");

        let manifest = base64::engine::general_purpose::STANDARD
            .decode(provenance_base64)
            .context("Failed to decode reference value manifest as base 64")?;
        let manifest = std::str::from_utf8(&manifest)
            .context("Failed to decode reference value manifest as utf8 string")?;

        let mut rvs: Vec<ReferenceValue> = vec![];

        let xml = roxmltree::Document::parse(manifest)?;

        // Find the SWID Meta tag to get information about the reference value source
        let meta = xml
            .descendants()
            .find(|n| n.has_tag_name((SWID_NS, "Meta")))
            .ok_or(anyhow!("Could not find meta information."))?;
        let manufacturer = meta
            .attribute((RIMIM_NS, "PlatformManufacturerStr"))
            .ok_or(anyhow!("Could not find manufacturer information."))?
            .replace(" ", "_");
        let product = meta
            .attribute((RIMIM_NS, "PlatformModel"))
            .ok_or(anyhow!("Could not find product information."))?;
        let version = meta
            .attribute("colloquialVersion")
            .ok_or(anyhow!("Could not find version information."))?
            .replace(".", "_");

        let rv_name_prefix = format!("{manufacturer}.{product}.{version}");
        info!("Extracting reference values for {rv_name_prefix}");

        // Parse the payload to find reference values.
        let payload = xml
            .descendants()
            .find(|n| n.has_tag_name((SWID_NS, "Payload")))
            .ok_or(anyhow!("Could not find SWID payload."))?;

        for resource in payload
            .descendants()
            .filter(|n| n.has_tag_name((SWID_NS, "Resource")))
            .filter(|n| n.attribute("type").unwrap_or("") == "Measurement")
        {
            let measurement_name = resource
                .attribute("name")
                .ok_or(anyhow!("Could not find measurement name"))?;

            // Resource may have multiple hash attributes
            let mut hash_index = 0;
            loop {
                let hash = resource.attribute((HASH_NS, format!("Hash{hash_index}").as_str()));
                if hash.is_none() {
                    break;
                }

                let rv_pair = HashValuePair::new(DEFAULT_ALG.into(), hash.unwrap().to_string());
                let name = format!("{rv_name_prefix}.{measurement_name}.hash{hash_index}");

                // Rego does not like dashes
                let name = name.replace("-", "_");

                let expiration = Utc::now()
                    .with_nanosecond(0)
                    .and_then(|t| t.checked_add_months(Months::new(MONTHS_BEFORE_EXPIRATION)))
                    .unwrap(); // The expiration time is fixed.

                let rv = ReferenceValue {
                    version: REFERENCE_VALUE_VERSION.into(),
                    name: name.to_string(),
                    expiration,
                    hash_value: vec![rv_pair],
                };
                rvs.push(rv);

                hash_index += 1;
            }
        }
        debug!("Reference Values Extracted: {:?}", rvs);
        Ok(rvs)
    }
}

#[cfg(test)]
mod tests {
    use super::SwidExtractor;
    use crate::extractors::extractor_modules::Extractor;

    #[test]
    fn extract_test_rim() {
        let extractor = SwidExtractor::default();
        let rvs = extractor
            .verify_and_extract(include_str!("test-rim.b64"))
            .unwrap();

        let mut found = false;
        for rv in rvs {
            if rv.name == "NVIDIA_Corporation.GH100.96_00_74_00_1C.Measurement_12.hash1" {
                if rv.hash_value[0].value() == "758af96044c700f98a85347be27124d51c05b8784ba216b629b9aaab6d538c759aed9922a133e4ac473564d359b271d5" {
                    found = true;
                    break
                }
            }
        }

        assert!(found);
    }
}
