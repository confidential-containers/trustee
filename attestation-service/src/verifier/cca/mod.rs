// Copyright (c) 2023 Arm Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use base64::Engine;
use core::result::Result::Ok;
use ear::Ear;
use jsonwebtoken::{self as jwt};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha384};
use std::str;
use veraison_apiclient::*;

const VERAISON_ADDR: &str = "VERAISON_ADDR";
const DEFAULT_VERAISON_ADDR: &str = "localhost:8080";
const MEDIA_TYPE: &str = "application/eat-collection; profile=http://arm.com/CCA-SSD/1.0.0";

#[derive(Debug, Default)]
pub struct CCA {}

#[derive(Serialize, Deserialize)]
struct CcaEvidence {
    /// CCA token
    token: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct RealmToken {
    //cca_realm_personalization_value: String,
    cca_realm_initial_measurement: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Evidence {
    cca_realm_delegated_token: RealmToken,
}

fn my_evidence_builder(
    nonce: &[u8],
    accept: &[String],
    token: Vec<u8>,
) -> Result<(Vec<u8>, String), veraison_apiclient::Error> {
    log::info!("server challenge: {:?}", nonce);
    log::info!("acceptable media types: {:#?}", accept);
    // TODO: Get the CCA media type from the slice of `accept`.
    Ok((token, MEDIA_TYPE.to_string()))
}

#[async_trait]
impl Verifier for CCA {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let evidence = serde_json::from_str::<CcaEvidence>(&attestation.tee_evidence)
            .context("Deserialize CCA Evidence failed.")?;

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

        let mut hasher = Sha384::new();
        hasher.update(&nonce);
        hasher.update(&attestation.tee_pubkey.k_mod);
        hasher.update(&attestation.tee_pubkey.k_exp);
        let mut hash_of_nonce_pubkey = hasher.finalize().to_vec();
        hash_of_nonce_pubkey.resize(64, 0);

        log::info!(
            "HASH(nonce||pubkey):\n\t{}\n",
            hex::encode(&hash_of_nonce_pubkey)
        );

        let token = evidence.token;
        let n = Nonce::Value(hash_of_nonce_pubkey.clone());
        let result = match cr.run(n, my_evidence_builder, token.clone()).await {
            Err(e) => {
                log::error!("Error: {}", e);
                bail!("CCA Attestation failed with error: {:?}", e);
            }
            Ok(attestation_result) => attestation_result,
        };

        // Get back the pub key to decrypt the ear which holds raw evidence and the session nonce
        let public_key_pem = verification_api.ear_verification_key_as_pem()?;
        let dk = jwt::DecodingKey::from_ec_pem(public_key_pem.as_bytes())
            .context("get the decoding key from the pem public key")?;
        let plain_ear = Ear::from_jwt(result.as_str(), jwt::Algorithm::ES256, &dk)
            .context("decrypt the ear with the decoding key")?;

        let ear_nonce = plain_ear.nonce.context("get nonce from ear")?;
        let nonce_byte = base64::engine::general_purpose::URL_SAFE
            .decode(ear_nonce.to_string())
            .context("decode nonce byte from ear")?;

        if hash_of_nonce_pubkey != nonce_byte {
            bail!("HASH(nonce||pubkey) is different from that in ear's session nonce");
        }

        // NOTE: The tcb returned is actually an empty `Evidence`, the code here is just a show case the parse of the CCA token
        // to get the tcb is possible, but this is not actually fully implemented due to the below reasons:
        // 1. CCA validation by the Verasion has some overlapping with the RVPS, the similar validation has been done by the Verasion already.
        // 2. Each of key of the CCA token layout after the parse is an int from hex, it cannot be converted into a json easily without
        // manually manipulation, which is dirty and complex, we can hold this for an while and see if the type of key can be redefined as String.
        let tcb = parse_cca_token(token)?;
        // Return Evidence parsed claim
        cca_generate_parsed_claim(tcb).map_err(|e| anyhow!("error from CCA Verifier: {:?}", e))
    }
}

/// The expected token layout looks like below,
///
/// In short:
/// {
/// "cca-platform-token" (44234): {
///     ...
///   },
/// "cca-realm-delegated-token" (44241): {
///     ...
///   }
/// }
///
/// and the details for each of them is listed here:
///
/// {
///     265_1: "http://arm.com/CCA-SSD/1.0.0",
///     10: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///     2396_1: h'7f454c4602010100000000000000000003003e000100000050580000000000004000000000000000a0030200000000000000000040003800090040001c001b00',
///     256_1: h'0107060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///     2401_1: h'0107060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///     2395_1: 12291_1,
///     2402_1: "sha-256",
///     2399_1: [
///         {
///             1: "BL",
///             5: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///             4: "3.4.2",
///             2: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///             6: "sha-256",
///         },
///         {
///             1: "M1",
///             5: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///             4: "1.2",
///             2: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///         },
///         {
///             1: "M2",
///             5: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///             4: "1.2.3",
///             2: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///         },
///         {
///             1: "M3",
///             5: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///             4: "1",
///             2: h'07060504030201000f0e0d0c0b0a090817161514131211101f1e1d1c1b1a1918',
///         },
///     ],
///     2400_1: "whatever.com",
/// }
/// {
///     10: h'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
///     44235_1: h'00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000',
///     44237_1: h'0476f988091be585ed41801aecfab858548c63057e16b0e676120bbd0d2f9c29e056c5d41a0130eb9c21517899dc23146b28e1b062bd3ea4b315fd219f1cbb528cb6e74ca49be16773734f61a1ca61031b2bbf3d918f2f94ffc4228e50919544ae',
///     44236_1: "sha-256",
///     44240_1: "sha-256",
///     44238_1: h'75a1fbc79a7d20a5ff843b914dfd8093d40cd07dd633401c8c42d697be224801',
///     44239_1: [
///         h'0000000000000000000000000000000000000000000000000000000000000000',
///         h'0000000000000000000000000000000000000000000000000000000000000000',
///         h'0000000000000000000000000000000000000000000000000000000000000000',
///         h'0000000000000000000000000000000000000000000000000000000000000000',
///     ],
/// }
fn parse_cca_token(token: Vec<u8>) -> Result<Evidence> {
    let evidence = Evidence {
        cca_realm_delegated_token: RealmToken {
            cca_realm_initial_measurement: "".to_string(),
        },
    };

    // NOTE: For some corner case, the date cannot be parsed to token correctly but the token
    // can be validated successfully by the CCA verifier e.g. `Err` value: Todo("Remaining bytes (00)")'
    // Instead of throwing an error, just print it out in this case.
    let mut di = match cbor_diag::parse_bytes(token) {
        Ok(di) => di,
        Err(err) => {
            log::info!("Error: {:?}", err);
            return Ok(evidence);
        }
    };

    if let cbor_diag::DataItem::Tag {
        tag: _,
        bitwidth: _,
        value,
    } = di
    {
        di = *value;
    }

    if let cbor_diag::DataItem::Map { data, .. } = di {
        for item in data {
            let cbor_diag::DataItem::ByteString(t) = item.1 else {
                anyhow::bail!("DateItem is not a ByteString");
            };

            let val = cbor_diag::parse_bytes(t.data)?;

            let cbor_diag::DataItem::Tag { value, .. } = val else {
                anyhow::bail!("DateItem is not a Tag");
            };

            let cbor_diag::DataItem::Array { data, .. } = *value else {
                anyhow::bail!("DateItem is not a Array");
            };

            if let cbor_diag::DataItem::ByteString(cose) = data
                .get(2)
                .ok_or_else(|| anyhow!("Cannot get raw bytes from token"))?
            {
                let v = &cose.data;
                match cbor_diag::parse_bytes(v) {
                    Ok(claims) => {
                        info!("{}", claims.to_diag_pretty());
                    }
                    Err(e) => {
                        error!("Error parsing claims: {}", e);
                    }
                }
            };
        }
    }

    Ok(evidence)
}

fn cca_generate_parsed_claim(tcb: Evidence) -> Result<TeeEvidenceParsedClaim> {
    let mut claim_map = Map::new();

    claim_map.insert(
        "cca-realm-initial-measurement".to_string(),
        serde_json::Value::String(tcb.cca_realm_delegated_token.cca_realm_initial_measurement),
    );

    log::info!("\nParsed Evidence claims map: \n{:?}\n", &claim_map);

    Ok(Value::Object(claim_map) as TeeEvidenceParsedClaim)
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
