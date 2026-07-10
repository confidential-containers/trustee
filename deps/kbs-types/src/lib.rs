// Support using this crate without the standard library
#![cfg_attr(not(feature = "std"), no_std)]

// As long as there is a memory allocator, we can still use this crate
// without the rest of the standard library by using the `alloc` crate
#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod hash_algorithm;

pub use error::{KbsTypesError, Result};
pub use hash_algorithm::HashAlgorithm;

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{string::String, vec::Vec};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
#[cfg(feature = "std")]
use ear::{self, RawValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
#[cfg(all(feature = "std", not(feature = "alloc")))]
use std::string::String;

use strum::{AsRefStr, Display, EnumString};

#[derive(
    Serialize, Clone, Copy, Deserialize, Debug, Eq, Hash, PartialEq, AsRefStr, Display, EnumString,
)]
#[serde(rename_all = "lowercase")]
pub enum Tee {
    // Azure CVMs with vTPM attestation
    #[serde(rename = "az-snp-vtpm")]
    #[strum(serialize = "az-snp-vtpm")]
    AzSnpVtpm,
    #[serde(rename = "az-tdx-vtpm")]
    #[strum(serialize = "az-tdx-vtpm")]
    AzTdxVtpm,
    #[strum(serialize = "nvidia")]
    Nvidia,
    #[strum(serialize = "sgx")]
    Sgx,
    #[strum(serialize = "snp")]
    Snp,
    #[strum(serialize = "tdx")]
    Tdx,
    // Arm Confidential Compute Architecture
    #[strum(serialize = "cca")]
    Cca,
    // China Secure Virtualization
    #[strum(serialize = "csv")]
    Csv,
    // IBM Z Secure Execution
    #[strum(serialize = "se")]
    Se,

    /// Hygon DCU (Deep Computing Unit)
    #[strum(serialize = "hygondcu")]
    HygonDcu,

    /// DPU (Data Processing Unit) DICE attestation
    #[strum(serialize = "dpu")]
    Dpu,
    // Trusted Platform Module
    #[strum(serialize = "tpm")]
    Tpm,

    // These values are only used for testing an attestation server, and should not
    // be used in an actual attestation scenario.
    #[strum(serialize = "sample")]
    Sample,
    #[strum(serialize = "sampledevice")]
    SampleDevice,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Request {
    pub version: String,
    pub tee: Tee,
    #[serde(rename = "extra-params")]
    pub extra_params: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Challenge {
    pub nonce: String,
    #[serde(rename = "extra-params")]
    pub extra_params: Value,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "kty")]
pub enum TeePubKey {
    RSA {
        alg: String,
        #[serde(rename = "n")]
        k_mod: String,
        #[serde(rename = "e")]
        k_exp: String,
    },
    /// Elliptic Curve Keys
    /// fields defined in
    /// [RFC 7518 Section 6.1](https://www.rfc-editor.org/rfc/rfc7518.html#page-28)
    EC {
        crv: String,
        alg: String,
        x: String,
        y: String,
    },
    /// Algorithm Key Pair (AKP) key type for PQC algorithm support as per
    /// [draft-ietf-jose-pqc-kem-05](https://datatracker.ietf.org/doc/draft-ietf-jose-pqc-kem/)
    AKP {
        alg: String,
        #[serde(rename = "pub")]
        public_key: String,
    },
}

#[cfg(feature = "std")]
impl From<&TeePubKey> for ear::RawValue {
    fn from(tpk: &TeePubKey) -> RawValue {
        let mut map: Vec<(RawValue, RawValue)> = vec![];

        match tpk {
            TeePubKey::RSA { alg, k_mod, k_exp } => {
                map.push((
                    RawValue::String("kty".to_string()),
                    RawValue::String("RSA".to_string()),
                ));
                map.push((
                    RawValue::String("alg".to_string()),
                    RawValue::String(alg.clone()),
                ));
                map.push((
                    RawValue::String("n".to_string()),
                    RawValue::String(k_mod.clone()),
                ));
                map.push((
                    RawValue::String("e".to_string()),
                    RawValue::String(k_exp.clone()),
                ));
            }
            TeePubKey::EC { crv, alg, x, y } => {
                map.push((
                    RawValue::String("kty".to_string()),
                    RawValue::String("EC".to_string()),
                ));
                map.push((
                    RawValue::String("crv".to_string()),
                    RawValue::String(crv.clone()),
                ));
                map.push((
                    RawValue::String("alg".to_string()),
                    RawValue::String(alg.clone()),
                ));
                map.push((
                    RawValue::String("x".to_string()),
                    RawValue::String(x.clone()),
                ));
                map.push((
                    RawValue::String("y".to_string()),
                    RawValue::String(y.clone()),
                ));
            }
            TeePubKey::AKP { alg, public_key } => {
                map.push((
                    RawValue::String("kty".to_string()),
                    RawValue::String("AKP".to_string()),
                ));
                map.push((
                    RawValue::String("alg".to_string()),
                    RawValue::String(alg.clone()),
                ));
                map.push((
                    RawValue::String("pub".to_string()),
                    RawValue::String(public_key.clone()),
                ));
            }
        }

        RawValue::Map(map)
    }
}

/// Data generated during the attestation process between client and server. Relevant only to the
/// client-server pairing.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RuntimeData {
    /// Nonce string generated by server.
    pub nonce: String,

    /// TEE public key generated by client.
    #[serde(rename = "tee-pubkey")]
    pub tee_pubkey: TeePubKey,
}

/// Combined evidence of all TEE devices found within a client.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompositeEvidence {
    /// Primary TEE evidence. Deserialization dependent on underlying attestation service.
    pub primary_evidence: Value,

    /// Additional evidence for secondary TEE devices within a client. JSON mapping of:
    ///
    /// Tee --> (TEE class, TEE evidence)
    ///
    /// Represented as string to avoid {de}serialization inconsistencies.
    pub additional_evidence: String,
}

/// Initialization data injected from an untrusted host into a TEE guest.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InitData {
    /// Format that INITDATA body should be deserialized/read to. Dependent on attestation service.
    pub format: String,

    /// Initialization data contents.
    pub body: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
pub struct Attestation {
    pub init_data: Option<InitData>,
    pub runtime_data: RuntimeData,
    pub tee_evidence: CompositeEvidence,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ProtectedHeader {
    /// Enryption algorithm for encrypted key
    pub alg: String,
    /// Encryption algorithm for payload
    pub enc: String,

    /// Other fields of Protected Header
    #[serde(skip_serializing_if = "Map::is_empty", flatten)]
    pub other_fields: Map<String, Value>,
}

impl ProtectedHeader {
    /// The generation of AAD for JWE follows [A.3.5 RFC7516](https://www.rfc-editor.org/rfc/rfc7516#appendix-A.3.5)
    pub fn generate_aad(&self) -> Result<Vec<u8>> {
        let protected_utf8 = serde_json::to_string(&self).map_err(|_| KbsTypesError::Serde)?;
        let aad = BASE64_URL_SAFE_NO_PAD.encode(protected_utf8);
        Ok(aad.into_bytes())
    }
}

fn serialize_base64_protected_header<S>(
    sub: &ProtectedHeader,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let protected_header_json = serde_json::to_string(sub).map_err(serde::ser::Error::custom)?;
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(protected_header_json);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64_protected_header<'de, D>(
    deserializer: D,
) -> core::result::Result<ProtectedHeader, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;
    let protected_header = serde_json::from_slice(&decoded).map_err(serde::de::Error::custom)?;

    Ok(protected_header)
}

fn serialize_base64<S>(sub: &Vec<u8>, serializer: S) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = BASE64_URL_SAFE_NO_PAD.encode(sub);
    serializer.serialize_str(&encoded)
}

fn deserialize_base64<'de, D>(deserializer: D) -> core::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let encoded = String::deserialize(deserializer)?;
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(serde::de::Error::custom)?;

    Ok(decoded)
}

fn serialize_base64_vec<S>(
    sub: &Option<Vec<u8>>,
    serializer: S,
) -> core::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match sub {
        Some(value) => {
            let encoded = String::from_utf8(value.clone()).map_err(serde::ser::Error::custom)?;
            serializer.serialize_str(&encoded)
        }
        None => serializer.serialize_none(),
    }
}

fn deserialize_base64_vec<'de, D>(
    deserializer: D,
) -> core::result::Result<Option<Vec<u8>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let string = String::deserialize(deserializer)?;
    let bytes = string.into_bytes();

    Ok(Some(bytes))
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Response {
    #[serde(
        serialize_with = "serialize_base64_protected_header",
        deserialize_with = "deserialize_base64_protected_header"
    )]
    pub protected: ProtectedHeader,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub encrypted_key: Vec<u8>,

    #[serde(
        skip_serializing_if = "Option::is_none",
        default = "Option::default",
        serialize_with = "serialize_base64_vec",
        deserialize_with = "deserialize_base64_vec"
    )]
    pub aad: Option<Vec<u8>>,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub iv: Vec<u8>,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub ciphertext: Vec<u8>,

    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub tag: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ErrorInformation {
    #[serde(rename = "type")]
    pub error_type: String,
    pub detail: String,
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::*;

    #[cfg(all(feature = "alloc", not(feature = "std")))]
    use alloc::string::ToString;

    #[test]
    fn parse_request() {
        let data = r#"
        {
            "version": "0.0.0",
            "tee": "tdx",
            "extra-params": ""
        }"#;

        let request: Request = serde_json::from_str(data).unwrap();

        assert_eq!(request.version, "0.0.0");
        assert_eq!(request.tee, Tee::Tdx);
        assert_eq!(request.extra_params, "");
    }

    #[test]
    fn parse_challenge() {
        let data = r#"
        {
            "nonce": "42",
            "extra-params": ""
        }"#;

        let challenge: Challenge = serde_json::from_str(data).unwrap();

        assert_eq!(challenge.nonce, "42");
        assert_eq!(challenge.extra_params, "");
    }

    #[test]
    fn protected_header_generate_aad() {
        let protected_header = ProtectedHeader {
            alg: "fakealg".to_string(),
            enc: "fakeenc".to_string(),
            other_fields: Map::new(),
        };

        let aad = protected_header.generate_aad().unwrap();

        assert_eq!(
            aad,
            "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9".as_bytes()
        );
    }

    #[test]
    fn parse_response() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");
        assert!(response.protected.other_fields.is_empty());
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, None);
    }

    #[test]
    fn parse_response_nested_protected_header() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyIsImVwayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiaFNEd0NZa3dwMVIwaTMzY3RENzNXZzJfT2cwbU9CcjA2NlNwanFxYlRtbyJ9fQo",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");

        let expected_other_fields = json!({
            "epk": {
                "kty" : "OKP",
                "crv": "X25519",
                "x": "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
            }
        })
        .as_object()
        .unwrap()
        .clone();

        assert_eq!(response.protected.other_fields, expected_other_fields);
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, None);
    }

    #[test]
    fn parse_response_with_aad() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyJ9Cg",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "aad": "fakeaad",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");
        assert!(response.protected.other_fields.is_empty());
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, Some("fakeaad".into()));
    }

    #[test]
    fn parse_response_with_protectedheader() {
        let data = r#"
        {
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyIsImZha2VmaWVsZCI6ImZha2V2YWx1ZSJ9",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "aad": "fakeaad",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        }"#;

        let response: Response = serde_json::from_str(data).unwrap();

        assert_eq!(response.protected.alg, "fakealg");
        assert_eq!(response.protected.enc, "fakeenc");
        assert_eq!(response.protected.other_fields["fakefield"], "fakevalue");
        assert_eq!(response.encrypted_key, "fakekey".as_bytes());
        assert_eq!(response.iv, "randomdata".as_bytes());
        assert_eq!(response.ciphertext, "fakeencoutput".as_bytes());
        assert_eq!(response.tag, "faketag".as_bytes());
        assert_eq!(response.aad, Some("fakeaad".into()));
    }

    #[test]
    fn serialize_response() {
        let response = Response {
            protected: ProtectedHeader {
                alg: "fakealg".into(),
                enc: "fakeenc".into(),
                other_fields: [("fakefield".into(), "fakevalue".into())]
                    .into_iter()
                    .collect(),
            },
            encrypted_key: "fakekey".as_bytes().to_vec(),
            iv: "randomdata".as_bytes().to_vec(),
            aad: Some("fakeaad".into()),
            tag: "faketag".as_bytes().to_vec(),
            ciphertext: "fakeencoutput".as_bytes().to_vec(),
        };

        let expected = json!({
            "protected": "eyJhbGciOiJmYWtlYWxnIiwiZW5jIjoiZmFrZWVuYyIsImZha2VmaWVsZCI6ImZha2V2YWx1ZSJ9",
            "encrypted_key": "ZmFrZWtleQ",
            "iv": "cmFuZG9tZGF0YQ",
            "aad": "fakeaad",
            "ciphertext": "ZmFrZWVuY291dHB1dA",
            "tag": "ZmFrZXRhZw"
        });

        let serialized = serde_json::to_value(&response).unwrap();
        assert_eq!(serialized, expected);
    }

    #[test]
    fn parse_attestation_ec() {
        let data = r#"
        {
            "runtime-data": {
                "nonce": "test_nonce",
                "tee-pubkey": {
                    "kty": "EC",
                    "crv": "fakecrv",
                    "alg": "fakealgorithm",
                    "x": "fakex",
                    "y": "fakey"
                }
            },
            "tee-evidence": {
                "primary_evidence": "test_primary_evidence",
                "additional_evidence": "test_additional_evidence"
            }
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();
        let tee_pubkey = attestation.runtime_data.tee_pubkey;

        let TeePubKey::EC { alg, crv, x, y } = tee_pubkey else {
            panic!("Must be an EC key");
        };

        assert_eq!(alg, "fakealgorithm");
        assert_eq!(crv, "fakecrv");
        assert_eq!(x, "fakex");
        assert_eq!(y, "fakey");
        assert_eq!(
            attestation.tee_evidence.primary_evidence,
            "test_primary_evidence"
        );
        assert_eq!(
            attestation.tee_evidence.additional_evidence,
            "test_additional_evidence"
        );
    }

    #[test]
    fn parse_attestation_rsa() {
        let data = r#"
        {
            "runtime-data": {
                "nonce": "test_nonce",
                "tee-pubkey": {
                    "kty": "RSA",
                    "alg": "fakealgorithm",
                    "n": "fakemodulus",
                    "e": "fakeexponent"
                }
            },
            "tee-evidence": {
                "primary_evidence": "test_primary_evidence",
                "additional_evidence": "test_additional_evidence"
            }
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();
        let tee_pubkey = attestation.runtime_data.tee_pubkey;

        let TeePubKey::RSA { alg, k_mod, k_exp } = tee_pubkey else {
            panic!("Must be a RSA key");
        };

        assert_eq!(attestation.runtime_data.nonce, "test_nonce");
        assert_eq!(alg, "fakealgorithm");
        assert_eq!(k_mod, "fakemodulus");
        assert_eq!(k_exp, "fakeexponent");
        assert_eq!(
            attestation.tee_evidence.primary_evidence,
            "test_primary_evidence"
        );
        assert_eq!(
            attestation.tee_evidence.additional_evidence,
            "test_additional_evidence"
        );
    }

    #[test]
    fn parse_attestation_akp() {
        let data = r#"
        {
            "runtime-data": {
                "nonce": "test_nonce",
                "tee-pubkey": {
                    "kty": "AKP",
                    "alg": "fakealgorithm",
                    "pub": "fakepublickey"
                }
            },
            "tee-evidence": {
                "primary_evidence": "test_primary_evidence",
                "additional_evidence": "test_additional_evidence"
            }
        }"#;

        let attestation: Attestation = serde_json::from_str(data).unwrap();
        let tee_pubkey = attestation.runtime_data.tee_pubkey;

        let TeePubKey::AKP { alg, public_key } = tee_pubkey else {
            panic!("Must be a AKP key");
        };

        assert_eq!(attestation.runtime_data.nonce, "test_nonce");
        assert_eq!(alg, "fakealgorithm");
        assert_eq!(public_key, "fakepublickey");
        assert_eq!(
            attestation.tee_evidence.primary_evidence,
            "test_primary_evidence"
        );
        assert_eq!(
            attestation.tee_evidence.additional_evidence,
            "test_additional_evidence"
        );
    }

    #[test]
    fn parse_error_information() {
        let data = r#"
        {
            "type": "problemtype",
            "detail": "problemdetail"
        }"#;

        let info: ErrorInformation = serde_json::from_str(data).unwrap();

        assert_eq!(info.error_type, "problemtype");
        assert_eq!(info.detail, "problemdetail");
    }

    #[test]
    #[cfg(feature = "std")]
    fn tee_pubkey_ear_json_deserialize() {
        // RSA key.
        let tpk = TeePubKey::RSA {
            alg: "test".to_string(),
            k_mod: "test".to_string(),
            k_exp: "test".to_string(),
        };
        let ear_raw: RawValue = (&tpk).into();
        let json_str = serde_json::to_string(&ear_raw).unwrap();
        assert_eq!(json_str, serde_json::to_string(&tpk).unwrap());

        // EC key.
        let tpk = TeePubKey::EC {
            crv: "test".to_string(),
            alg: "test".to_string(),
            x: "test".to_string(),
            y: "test".to_string(),
        };
        let ear_raw: RawValue = (&tpk).into();
        let json_str = serde_json::to_string(&ear_raw).unwrap();
        assert_eq!(json_str, serde_json::to_string(&tpk).unwrap());

        // AKP key.
        let tpk = TeePubKey::AKP {
            alg: "test".to_string(),
            public_key: "test".to_string(),
        };
        let ear_raw: RawValue = (&tpk).into();
        let json_str = serde_json::to_string(&ear_raw).unwrap();
        assert_eq!(json_str, serde_json::to_string(&tpk).unwrap());
    }

    #[test]
    fn tee_as_ref() {
        assert_eq!(Tee::AzSnpVtpm.as_ref(), "az-snp-vtpm");
        assert_eq!(Tee::AzTdxVtpm.as_ref(), "az-tdx-vtpm");
        assert_eq!(Tee::Nvidia.as_ref(), "nvidia");
        assert_eq!(Tee::Sgx.as_ref(), "sgx");
        assert_eq!(Tee::Snp.as_ref(), "snp");
        assert_eq!(Tee::Tdx.as_ref(), "tdx");
        assert_eq!(Tee::Cca.as_ref(), "cca");
        assert_eq!(Tee::Csv.as_ref(), "csv");
        assert_eq!(Tee::Se.as_ref(), "se");
        assert_eq!(Tee::HygonDcu.as_ref(), "hygondcu");
        assert_eq!(Tee::Tpm.as_ref(), "tpm");
        assert_eq!(Tee::Sample.as_ref(), "sample");
        assert_eq!(Tee::SampleDevice.as_ref(), "sampledevice");
    }

    #[cfg(feature = "std")]
    #[test]
    fn tee_from_str() {
        use std::str::FromStr;

        assert_eq!(Tee::from_str("az-snp-vtpm").unwrap(), Tee::AzSnpVtpm);
        assert_eq!(Tee::from_str("az-tdx-vtpm").unwrap(), Tee::AzTdxVtpm);
        assert_eq!(Tee::from_str("nvidia").unwrap(), Tee::Nvidia);
        assert_eq!(Tee::from_str("sgx").unwrap(), Tee::Sgx);
        assert_eq!(Tee::from_str("snp").unwrap(), Tee::Snp);
        assert_eq!(Tee::from_str("tdx").unwrap(), Tee::Tdx);
        assert_eq!(Tee::from_str("cca").unwrap(), Tee::Cca);
        assert_eq!(Tee::from_str("csv").unwrap(), Tee::Csv);
        assert_eq!(Tee::from_str("se").unwrap(), Tee::Se);
        assert_eq!(Tee::from_str("hygondcu").unwrap(), Tee::HygonDcu);
        assert_eq!(Tee::from_str("tpm").unwrap(), Tee::Tpm);
        assert_eq!(Tee::from_str("sample").unwrap(), Tee::Sample);
        assert_eq!(Tee::from_str("sampledevice").unwrap(), Tee::SampleDevice);
        Tee::from_str("invalid").unwrap_err();
    }
}
