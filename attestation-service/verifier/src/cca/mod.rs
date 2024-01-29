// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use anyhow::{Context, Result};
use thiserror::Error;
use async_trait::async_trait;
use base64::Engine;
use core::result::Result::Ok;
use ear::{Ear, RawValue};
use jsonwebtoken::{self as jwt};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, str};
use veraison_apiclient::*;

const VERAISON_ADDR: &str = "VERAISON_ADDR";
const DEFAULT_VERAISON_ADDR: &str = "localhost:8080";
const MEDIA_TYPE: &str = "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0";

#[derive(Debug, Default)]
pub struct CCA {}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SwComponent {
    pub measurement_type: String,
    pub measurement_value: String,
    pub version: String,
    pub signer_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CcaPlatformClaims {
    pub cca_platform_challenge: String,
    pub cca_platform_sw_components: Vec<SwComponent>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct RealmClaims {
    pub cca_realm_personalization_value: String,
    pub cca_realm_initial_measurement: String,
    pub cca_realm_extensible_measurements: Vec<String>,
    pub cca_realm_hash_algo_id: String,
    pub cca_realm_public_key_hash_algo_id: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Evidence {
    realm: RealmClaims,
    platform: CcaPlatformClaims,
}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    /// CCA token
    token: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum CCAError {
    #[error("CCA verifier must provide report data field!")]
    ReportDataMissing,
    #[error("Deserialize CCA Evidence failed: {0}")]
    FailedtoDeserializeCCAEvidence(String),
    #[error("CCA Attestation failed with error: {0}")]
    CCAAttestationFailed(String),
    #[error("get the decoding key from the pem public key: {0}")]
    GetDecodingKey(String),
    #[error("decrypt the ear with the decoding key: {0}")]
    DecryptDecodingKey(String),
    #[error("decode nonce byte from ear: {0}")]
    DecodeNonceByte(String),
    #[error("report data is different from that in ear's session nonce")]
    ReportDataMismatch,
    #[error("no entry found for CCA_SSD_PLATFORM")]
    NoEntryFound,
    #[error("init data hash is different from that in CCA token")]
    InitDataHashMismatch,
    #[error("Failed to decode base64: {0}")]
    FailedtoDecodeBase64(String),
    #[error("get platform evidence from the cca evidence map")]
    GetPlatformEvidence,
    #[error("Serde Json Error")]
    SerdeJson(#[from] serde_json::Error),
    #[error("get realm evidence from the cca evidence map")]
    GetRealmEvidence,
    #[error("CAA Verifier error: {0}")]
    CAAVerifier(String),
    #[error("verification error")]
    Verification(#[from] veraison_apiclient::Error),
    #[error("Failed to discover the verification endpoint details")]
    VerificationEndpoint(),
    #[error("anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),
}

fn my_evidence_builder(
    nonce: &[u8],
    accept: &[String],
    token: Vec<u8>,
) -> Result<(Vec<u8>, String), veraison_apiclient::Error> {
    info!("server challenge: {:?}", nonce);
    info!("acceptable media types: {:#?}", accept);
    // TODO: Get the CCA media type from the slice of `accept`.
    Ok((token, MEDIA_TYPE.to_string()))
}

#[async_trait]
impl Verifier for CCA {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim, CCAError> {
        let ReportData::Value(expected_report_data) = expected_report_data else {
            return Err(CCAError::ReportDataMissing);
        };

        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "CCA");

        let evidence = serde_json::from_slice::<CcaEvidence>(evidence)
            .map_err(|err| CCAError::FailedtoDeserializeCCAEvidence(err.to_string()))?;

        let host_url =
            std::env::var(VERAISON_ADDR).unwrap_or_else(|_| DEFAULT_VERAISON_ADDR.to_string());

        let discovery = Discovery::from_base_url(format!("http://{:}", host_url))?;

        let verification_api = discovery.get_verification_api().await?;

        let relative_endpoint = verification_api
            .get_api_endpoint("newChallengeResponseSession")
            .context("Failed to discover the verification endpoint details.")?;

        let api_endpoint = format!("http://{:}{}", host_url, relative_endpoint);

        // create a ChallengeResponse object
        let cr = ChallengeResponseBuilder::new()
            .with_new_session_url(api_endpoint)
            .build()?;

        let token = evidence.token;
        let n = Nonce::Value(expected_report_data.clone());
        let result = match cr.run(n, my_evidence_builder, token.clone()).await {
            Err(e) => {
                return Err(CCAError::CCAAttestationFailed(e.to_string()));
            }
            Ok(attestation_result) => attestation_result,
        };

        // Get back the pub key to decrypt the ear which holds raw evidence and the session nonce
        let public_key_pem = verification_api.ear_verification_key_as_pem()?;
        let dk = jwt::DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .map_err(|err| CCAError::GetDecodingKey(err.to_string()))?;
        let plain_ear = Ear::from_jwt(result.as_str(), jwt::Algorithm::ES256, &dk)
            .map_err(|err| CCAError::DecryptDecodingKey(err.to_string()))?;

        let ear_nonce = plain_ear.nonce.context("get nonce from ear")?;
        let nonce_byte = base64::engine::general_purpose::STANDARD
            .decode(ear_nonce.to_string())
            .map_err(|err| CCAError::DecodeNonceByte(err.to_string()))?;

        if expected_report_data != nonce_byte {
            return Err(CCAError::ReportDataMismatch);
        }

        let cca_mod = match plain_ear.submods.get("CCA_SSD_PLATFORM") {
            Some(value) => value,
            None => return Err(CCAError::NoEntryFound),
        };
        let evidence = &cca_mod.annotated_evidence;

        // NOTE: CCA validation by the Verasion has some overlapping with the RVPS, the similar validation has been done by the Verasion already.
        // The generation of CCA evidence here is to align with other verifier, e.g. TDX, to support initdata mechanism and RVPS if that is the case of future planning.
        let tcb = parse_cca_evidence(evidence)?;

        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            debug!("Check the binding of init data.");
            if *expected_init_data_hash
                != base64::engine::general_purpose::STANDARD
                    .decode(&tcb.realm.cca_realm_personalization_value)
                    .map_err(|err| CCAError::FailedtoDecodeBase64(err.to_string()))?
                    .as_slice()
            {
                return Err(CCAError::InitDataHashMismatch);
            }
        }

        // Return Evidence parsed claim
        cca_generate_parsed_claim(tcb).map_err(|e| CCAError::CAAVerifier(e.to_string()))
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
fn parse_cca_evidence(evidence_map: &BTreeMap<String, RawValue>) -> Result<Evidence, CCAError> {
    let mut evidence = Evidence::default();
    let platfrom = evidence_map
        .get("platform")
        .context("get platform evidence from the cca evidence map")?;

    let output = serde_json::to_string(platfrom)?;
    let p: CcaPlatformClaims = serde_json::from_str(output.as_str())?;
    evidence.platform = p;

    let realm = evidence_map
        .get("realm")
        .context("get realm evidence from the cca evidence map")?;
    let output = serde_json::to_string(realm)?;
    let r: RealmClaims = serde_json::from_str(output.as_str())?;
    evidence.realm = r;

    Ok(evidence)
}

fn cca_generate_parsed_claim(tcb: Evidence) -> Result<TeeEvidenceParsedClaim> {
    let v = serde_json::to_value(tcb)?;
    Ok(v as TeeEvidenceParsedClaim)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_cca_generate_parsed_claim() {
        let s = fs::read("../test_data/cca-claims.json").unwrap();
        let evidence = String::from_utf8_lossy(&s);
        let tcb = serde_json::from_str::<Evidence>(&evidence).unwrap();
        let parsed_claim = cca_generate_parsed_claim(tcb);
        assert!(parsed_claim.is_ok());
        let _ = fs::write(
            "test_data/cca_evidence_claim_output.txt",
            format!("{:?}", parsed_claim.unwrap()),
        );
    }
}
