// Copyright (c) 2023 Arm Ltd.
// Copyright (c) 2025 Linaro Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use anyhow::anyhow;
use async_trait::async_trait;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use core::result::Result::Ok;
use ear::{Ear, RawValue};
use log::debug;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{collections::BTreeMap, str};
use veraison_apiclient::*;

mod config;
use config::{Config, DEFAULT_CCA_CONFIG};
mod local;
mod remote;

const CCA_CONFIG_FILE: &str = "CCA_CONFIG_FILE";

#[derive(Debug, Default)]
pub struct CCA {}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SwComponent {
    pub measurement_type: String,
    pub measurement_value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub signer_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CcaPlatformClaims {
    pub cca_platform_instance_id: String,
    pub cca_platform_implementation_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RealmClaims {
    pub cca_realm_personalization_value: String,
    pub cca_realm_initial_measurement: String,
    pub cca_realm_extensible_measurements: Vec<String>,
    pub cca_realm_hash_algo_id: String,
    pub cca_realm_challenge: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct EvidenceClaimsSet {
    realm: RealmClaims,
    platform: CcaPlatformClaims,
    report_data: String,
    init_data: String,
}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    /// CCA token bytes
    token: Vec<u8>,
}

fn unwrap_evidence(wrapped_evidence: &[u8]) -> Result<String> {
    // The value of the request's "tee-evidence" is a string containing the
    // JSON-encoded CcaEvidence, such as:
    //      "{ \"token\": [ 217, ... ] }"
    // We need to remove the surrounding quotes and unescape the JSON key
    // before passing it to serde.
    let s = str::from_utf8(&wrapped_evidence[1..wrapped_evidence.len() - 1])?;
    let u = s.replace("\\", "");

    Ok(u)
}

#[async_trait]
impl Verifier for CCA {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let config_file =
            std::env::var(CCA_CONFIG_FILE).unwrap_or_else(|_| DEFAULT_CCA_CONFIG.to_string());

        let config = Config::try_from(Path::new(&config_file))
            .map_err(|e| anyhow!("parsing {config_file}: {e}"))?;

        let ReportData::Value(expected_report_data) = expected_report_data else {
            bail!("CCA verifier must provide report data field!");
        };

        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "CCA");

        let evidence = unwrap_evidence(evidence)?;
        let evidence = serde_json::from_str::<CcaEvidence>(&evidence)
            .context("Deserialize CCA Evidence failed.")?;

        let ear: Ear = match config.cca_verifier {
            config::CcaVerifierConfig::Remote { .. } => {
                remote::verify(config, &evidence.token, &expected_report_data).await?
            }
            config::CcaVerifierConfig::Local { .. } => {
                local::verify(config, &evidence.token, &expected_report_data)?
            }
        };

        let realm_mod = match ear.submods.get("CCA_REALM") {
            Some(value) => value,
            None => bail!("no entry found for CCA_REALM"),
        };
        let realm_claims = &realm_mod.annotated_evidence;

        let platform_mod = match ear.submods.get("CCA_SSD_PLATFORM") {
            Some(value) => value,
            None => bail!("no entry found for CCA_SSD_PLATFORM"),
        };
        let platform_claims = &platform_mod.annotated_evidence;

        let tcb = assemble_cca_evidence(realm_claims, platform_claims)?;

        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            debug!("Check the binding of init data");
            if *expected_init_data_hash
                != base64::engine::general_purpose::STANDARD
                    .decode(&tcb.realm.cca_realm_personalization_value)
                    .context("Failed to decode base64")?
                    .as_slice()
            {
                bail!("init data hash is different from that in CCA token");
            }
        }

        // Return Evidence parsed claim
        cca_generate_parsed_claim(tcb).map_err(|e| anyhow!("error from CCA Verifier: {:?}", e))
    }
}

/// The expected evidence layout looks like below,
///
/// In short:
/// {
/// "platform": {
///     ...
///   },
/// "realm": {
///     ...
///   }
/// }
///
/// and the details for each of them is listed here:
///
/// {
///    "platform":{
///       "cca-platform-challenge":"tZc8touqn8VVWHhrfsZ/aeQN9bpaqSHNDCf0BYegEeo=",
///       "cca-platform-config":"AQcGBQQDAgEADw4NDAsKCQgXFhUUExIREB8eHRwbGhkY",
///       "cca-platform-hash-algo-id":"sha-256",
///       "cca-platform-implementation-id":"f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAUFgAAAAAAAA=",
///       "cca-platform-instance-id":"AQcGBQQDAgEADw4NDAsKCQgXFhUUExIREB8eHRwbGhkY",
///       "cca-platform-lifecycle":12291,
///       "cca-platform-profile":"http://arm.com/CCA-SSD/1.0.0",
///       "cca-platform-service-indicator":"whatever.com",
///       "cca-platform-sw-components":[
///          {
///             "measurement-description":"TF-M_SHA256MemPreXIP",
///             "measurement-type":"BL",
///             "measurement-value":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "signer-id":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "version":"3.4.2"
///          },
///          {
///             "measurement-type":"M1",
///             "measurement-value":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "signer-id":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "version":"1.2"
///          },
///          {
///             "measurement-type":"M2",
///             "measurement-value":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "signer-id":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "version":"1.2.3"
///          },
///          {
///             "measurement-type":"M3",
///             "measurement-value":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "signer-id":"BwYFBAMCAQAPDg0MCwoJCBcWFRQTEhEQHx4dHBsaGRg=",
///             "version":"1"
///          }
///       ]
///    },
///    "realm":{
///       "cca-realm-challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
///       "cca-realm-extensible-measurements":[
///          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
///          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
///          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
///          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
///       ],
///       "cca-realm-hash-algo-id":"sha-256",
///       "cca-realm-initial-measurement":"EJHTwpx6vz58Z4/NjKCnmOse6cirEeEbPq06H/xIXUw=",
///       "cca-realm-personalization-value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
///       "cca-realm-public-key":"BHb5iAkb5YXtQYAa7Pq4WFSMYwV+FrDmdhILvQ0vnCngVsXUGgEw65whUXiZ3CMUayjhsGK9PqSzFf0hnxy7Uoy250ykm+Fnc3NPYaHKYQMbK789kY8vlP/EIo5QkZVErg==",
///       "cca-realm-public-key-hash-algo-id":"sha-256"
///    }
/// }
/// NOTE: each of the value are base64 encoded hex value.
fn assemble_cca_evidence(
    realm_claims: &BTreeMap<String, RawValue>,
    platform_claims: &BTreeMap<String, RawValue>,
) -> Result<EvidenceClaimsSet> {
    let mut evidence = EvidenceClaimsSet::default();

    let output = serde_json::to_string(platform_claims)?;
    let p: CcaPlatformClaims = serde_json::from_str(output.as_str())?;
    evidence.platform = p;

    let output = serde_json::to_string(realm_claims)?;
    let r: RealmClaims = serde_json::from_str(output.as_str())?;
    evidence.realm = r;

    // Populate the init_data and report_data claims with the expected values
    evidence.init_data = b642hex(&evidence.realm.cca_realm_personalization_value)?;
    evidence.report_data = b642hex(&evidence.realm.cca_realm_challenge)?;

    Ok(evidence)
}

fn b642hex(b64: &String) -> Result<String> {
    let buf = BASE64_STANDARD.decode(b64)?;
    Ok(hex::encode(&buf))
}

fn cca_generate_parsed_claim(tcb: EvidenceClaimsSet) -> Result<TeeEvidenceParsedClaim> {
    let v = serde_json::to_value(tcb).context("serializing CCA evidence claims into JSON")?;

    debug!("CCA claims-set: {v}");

    Ok(v as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_cca_generate_parsed_claim() {
        let s = fs::read("./test_data/cca-claims.json").unwrap();
        let evidence = String::from_utf8_lossy(&s);
        let tcb = serde_json::from_str::<EvidenceClaimsSet>(&evidence).unwrap();
        let parsed_claim = cca_generate_parsed_claim(tcb);
        assert!(parsed_claim.is_ok());
        let _ = fs::write(
            "test_data/cca_evidence_claim_output.txt",
            format!("{:?}", parsed_claim.unwrap()),
        );
    }
}
