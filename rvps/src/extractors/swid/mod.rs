// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;
use base64::Engine;
use log::{debug, info};
use serde::Deserialize;

use crate::ReferenceValue;

use super::Extractor;

#[derive(Deserialize, Clone, Debug, PartialEq, Default)]
pub struct SwidExtractorConfig;

#[derive(Default)]
pub struct SwidExtractor;

const SWID_NS: &str = "http://standards.iso.org/iso/19770/-2/2015/schema.xsd";
const RIMIM_NS: &str = "https://trustedcomputinggroup.org/resource/tcg-reference-integrity-manifest-rim-information-model/";
const HASH_NS: &str = "http://www.w3.org/2001/04/xmlenc#sha384";

impl SwidExtractor {
    pub fn new(_config: Option<SwidExtractorConfig>) -> Result<SwidExtractor> {
        Ok(SwidExtractor)
    }
}

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
        let edition = meta
            .attribute("edition")
            .ok_or(anyhow!("Could not find edition information."))?;

        let rv_name_prefix = format!("{manufacturer}.{edition}");
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
            let measurement_index = resource
                .attribute("index")
                .ok_or(anyhow!("Could not find measurement name"))?;

            let name = format!("{rv_name_prefix}.measurement_{measurement_index}");

            // Rego does not like dashes
            let name = name.replace("-", "_");

            // Resource may have multiple hash attributes.
            // Add these to a list that the policy can check
            // with the `in` operator.
            let mut measurement_value = vec![];

            let mut hash_index = 0;
            loop {
                let Some(hash) =
                    resource.attribute((HASH_NS, format!("Hash{hash_index}").as_str()))
                else {
                    break;
                };

                // If the hash only contains '0', move onto the next resource.
                // This could mean that the RIM is attesting that the hash should
                // be '0', but more commonly it means that there is no measurement
                // at this index.
                if hash.chars().all(|c| c == '0') {
                    hash_index += 1;
                    continue;
                }

                let hash_value = serde_json::Value::String(hash.to_string());
                measurement_value.push(hash_value);

                hash_index += 1;
            }

            // If the measurement has no non-zero hashes, skip it.
            // This will avoid collisions between multiple manifests
            // representing the same TCB.
            if measurement_value.is_empty() {
                continue;
            }
            let rv = ReferenceValue::new()?
                .set_name(&name)
                .set_value(serde_json::Value::Array(measurement_value));
            rvs.push(rv);
        }
        debug!("Reference Values Extracted: {:?}", rvs);
        Ok(rvs)
    }
}

#[cfg(test)]
mod tests {
    use super::SwidExtractor;
    use crate::extractors::Extractor;

    #[test]
    fn extract_test_rim() {
        let extractor = SwidExtractor;
        let rvs = extractor
            .verify_and_extract(include_str!("test-rim.b64"))
            .unwrap();

        let mut found = false;
        for rv in rvs {
            if rv.name == "NVIDIA_Corporation.GPU.measurement_12" &&rv.value()[0].as_str().unwrap() == "758af96044c700f98a85347be27124d51c05b8784ba216b629b9aaab6d538c759aed9922a133e4ac473564d359b271d5" {
                    found = true;
                    break
            }
        }

        assert!(found);
    }
}
