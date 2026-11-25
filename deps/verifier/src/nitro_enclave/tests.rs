// Copyright (c) 2026 XHawk Corp
// SPDX-License-Identifier: Apache-2.0

//! Tests for the AWS Nitro Enclaves verifier.
//!
//! The NSM is only reachable from inside an enclave, so the documents here are
//! generated: a P-384 root -> intermediate -> leaf chain and a COSE_Sign1 laid
//! out exactly as the NSM emits it (protected header `{1: -35}`, empty
//! unprotected header, CBOR payload, 96-byte raw r||s ES384 signature). The
//! verifier under test trusts the generated root instead of the AWS one.

use base64::Engine;
use coset::cbor::value::Value;
use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder, TaggedCborSerializable, iana};
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{BasicConstraints, KeyUsage};
use openssl::x509::{X509, X509Builder, X509NameBuilder};
use rstest::rstest;
use serde_json::json;

use super::*;
use crate::{InitDataHash, ReportData, Verifier};

const NOW: i64 = 1_763_560_000; // 2025-11-19T13:46:40Z, inside every generated validity window
const HOUR: i64 = 3600;
const REPORT_DATA: [u8; 48] = [0x11; 48];
const INIT_DATA_DIGEST: [u8; 32] = [0x22; 32];

fn p384_key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::SECP384R1).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

fn cert(
    cn: &str,
    key: &PKey<Private>,
    issuer: Option<(&X509, &PKey<Private>)>,
    ca: bool,
    not_before: i64,
    not_after: i64,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", cn).unwrap();
    let name = name.build();

    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    let mut serial = BigNum::new().unwrap();
    serial.rand(64, MsbOption::MAYBE_ZERO, false).unwrap();
    b.set_serial_number(&serial.to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(issuer.map(|(c, _)| c.subject_name()).unwrap_or(&name))
        .unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(not_before).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(not_after).unwrap())
        .unwrap();
    if ca {
        b.append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .unwrap(),
        )
        .unwrap();
    } else {
        b.append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        b.append_extension(
            KeyUsage::new()
                .critical()
                .digital_signature()
                .build()
                .unwrap(),
        )
        .unwrap();
    }
    let signer = issuer.map(|(_, k)| k).unwrap_or(key);
    b.sign(signer, MessageDigest::sha384()).unwrap();
    b.build()
}

/// A generated PKI shaped like AWS's: root -> intermediate -> leaf.
struct Pki {
    root: X509,
    intermediate: X509,
    intermediate_key: PKey<Private>,
    leaf: X509,
    leaf_key: PKey<Private>,
}

impl Pki {
    fn new() -> Self {
        Self::at(NOW)
    }

    /// A PKI whose certificates are all valid at `now`.
    fn at(now: i64) -> Self {
        let root_key = p384_key();
        let root = cert(
            "test.nitro-enclaves",
            &root_key,
            None,
            true,
            now - 365 * 24 * HOUR,
            now + 365 * 24 * HOUR,
        );
        let int_key = p384_key();
        let intermediate = cert(
            "test.zonal",
            &int_key,
            Some((&root, &root_key)),
            true,
            now - 24 * HOUR,
            now + 24 * HOUR,
        );
        let leaf_key = p384_key();
        let leaf = cert(
            "test.enclave",
            &leaf_key,
            Some((&intermediate, &int_key)),
            false,
            now - HOUR,
            now + 2 * HOUR,
        );
        Self {
            root,
            intermediate,
            intermediate_key: int_key,
            leaf,
            leaf_key,
        }
    }

    fn verifier(&self) -> NitroEnclave {
        NitroEnclave::with_trust_anchor(self.root.to_der().unwrap(), Some(NOW)).unwrap()
    }
}

/// The fields of an attestation document, before encoding.
struct Doc {
    module_id: Value,
    digest: Value,
    pcrs: Vec<(u64, Vec<u8>)>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    /// Payload entries replaced verbatim, to build malformed documents.
    overrides: Vec<(&'static str, Value)>,
}

fn pcr(byte: u8) -> Vec<u8> {
    vec![byte; 48]
}

impl Doc {
    fn new(pki: &Pki) -> Self {
        Self {
            module_id: Value::Text("i-0123456789abcdef0-enc0123456789abcdef".into()),
            digest: Value::Text("SHA384".into()),
            pcrs: vec![
                (0, pcr(0xa0)),
                (1, pcr(0xa1)),
                (2, pcr(0xa2)),
                (3, pcr(0xa3)),
                (4, pcr(0xa4)),
                (8, pcr(0xa8)),
            ],
            certificate: pki.leaf.to_der().unwrap(),
            cabundle: vec![
                pki.root.to_der().unwrap(),
                pki.intermediate.to_der().unwrap(),
            ],
            public_key: None,
            user_data: Some(INIT_DATA_DIGEST.to_vec()),
            nonce: Some(REPORT_DATA.to_vec()),
            overrides: vec![],
        }
    }

    fn payload(&self) -> Vec<u8> {
        let opt = |v: &Option<Vec<u8>>| v.clone().map(Value::Bytes).unwrap_or(Value::Null);
        let map = Value::Map(vec![
            (Value::Text("module_id".into()), self.module_id.clone()),
            (
                Value::Text("timestamp".into()),
                Value::Integer((NOW as u64 * 1000).into()),
            ),
            (Value::Text("digest".into()), self.digest.clone()),
            (
                Value::Text("pcrs".into()),
                Value::Map(
                    self.pcrs
                        .iter()
                        .map(|(i, v)| (Value::Integer((*i).into()), Value::Bytes(v.clone())))
                        .collect(),
                ),
            ),
            (
                Value::Text("certificate".into()),
                Value::Bytes(self.certificate.clone()),
            ),
            (
                Value::Text("cabundle".into()),
                Value::Array(self.cabundle.iter().cloned().map(Value::Bytes).collect()),
            ),
            (Value::Text("public_key".into()), opt(&self.public_key)),
            (Value::Text("user_data".into()), opt(&self.user_data)),
            (Value::Text("nonce".into()), opt(&self.nonce)),
        ]);
        let map = match map {
            Value::Map(mut entries) => {
                for (key, value) in &self.overrides {
                    let entry = entries
                        .iter_mut()
                        .find(|(k, _)| k.as_text() == Some(key))
                        .expect("override names a payload field");
                    entry.1 = value.clone();
                }
                Value::Map(entries)
            }
            _ => unreachable!(),
        };
        let mut out = vec![];
        coset::cbor::ser::into_writer(&map, &mut out).unwrap();
        out
    }

    /// COSE_Sign1, untagged, as the NSM returns it.
    fn sign(&self, key: &PKey<Private>, alg: iana::Algorithm) -> Vec<u8> {
        self.sign1(key, alg).to_vec().unwrap()
    }

    fn sign1(&self, key: &PKey<Private>, alg: iana::Algorithm) -> coset::CoseSign1 {
        let protected = HeaderBuilder::new().algorithm(alg).build();
        CoseSign1Builder::new()
            .protected(protected)
            .payload(self.payload())
            .create_signature(b"", |tbs| raw_es384(key, tbs))
            .build()
    }
}

fn raw_es384(key: &PKey<Private>, data: &[u8]) -> Vec<u8> {
    let digest = hash(MessageDigest::sha384(), data).unwrap();
    let sig = EcdsaSig::sign(&digest, &key.ec_key().unwrap()).unwrap();
    let mut out = sig.r().to_vec_padded(48).unwrap();
    out.extend(sig.s().to_vec_padded(48).unwrap());
    out
}

fn evidence(document: &[u8]) -> serde_json::Value {
    json!({
        "version": 1,
        "attestation_document": base64::engine::general_purpose::STANDARD.encode(document),
    })
}

async fn evaluate(
    verifier: &NitroEnclave,
    document: &[u8],
    report_data: &ReportData<'_>,
    init_data: &InitDataHash<'_>,
) -> anyhow::Result<serde_json::Value> {
    let mut claims = verifier
        .evaluate(evidence(document), report_data, init_data)
        .await?;
    assert_eq!(claims.len(), 1);
    let (claims, class) = claims.remove(0);
    assert_eq!(class, "cpu");
    Ok(claims)
}

async fn expect_err(verifier: &NitroEnclave, document: &[u8], needle: &str) {
    let err = evaluate(
        verifier,
        document,
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .expect_err("the document must be refused");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(needle),
        "expected an error containing {needle:?}, got: {msg}"
    );
}

#[tokio::test]
async fn accepts_a_valid_document_and_reports_its_claims() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);

    let claims = evaluate(
        &pki.verifier(),
        &doc,
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();

    assert_eq!(
        claims,
        json!({
            "module_id": "i-0123456789abcdef0-enc0123456789abcdef",
            "timestamp": NOW as u64 * 1000,
            "digest": "SHA384",
            "pcr0": hex::encode(pcr(0xa0)),
            "pcr1": hex::encode(pcr(0xa1)),
            "pcr2": hex::encode(pcr(0xa2)),
            "pcr8": hex::encode(pcr(0xa8)),
            "report_data": hex::encode(REPORT_DATA),
            "init_data": hex::encode(INIT_DATA_DIGEST),
        })
    );
}

#[tokio::test]
async fn reports_pcr17_for_a_nitro_sandbox_pod() {
    // An EKS Nitro Sandbox measures the pod's Cedar policy into PCR17; that, not the
    // guest image, is what tells one workload from another.
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.pcrs.push((17, pcr(0xb7)));
    let doc = doc.sign(&pki.leaf_key, iana::Algorithm::ES384);

    let claims = evaluate(
        &pki.verifier(),
        &doc,
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();

    assert_eq!(claims["pcr17"], json!(hex::encode(pcr(0xb7))));
    assert_eq!(claims["pcr0"], json!(hex::encode(pcr(0xa0))));
    assert!(claims.get("pcr3").is_none() && claims.get("pcr4").is_none());
}

#[tokio::test]
async fn accepts_the_tagged_cose_sign1_form() {
    let pki = Pki::new();
    let doc = Doc::new(&pki)
        .sign1(&pki.leaf_key, iana::Algorithm::ES384)
        .to_tagged_vec()
        .unwrap();
    evaluate(
        &pki.verifier(),
        &doc,
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn reports_public_key_when_present() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.public_key = Some(vec![0x30, 0x59, 0x01]);
    let claims = evaluate(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();
    assert_eq!(claims["public_key"], "305901");
}

#[tokio::test]
async fn reports_empty_bindings_when_nothing_is_expected_or_present() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.nonce = None;
    doc.user_data = None;
    let claims = evaluate(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        &ReportData::NotProvided,
        &InitDataHash::NotProvided,
    )
    .await
    .unwrap();
    assert_eq!(claims["report_data"], "");
    assert_eq!(claims["init_data"], "");
}

#[tokio::test]
async fn refuses_a_tampered_signature() {
    let pki = Pki::new();
    let mut sign1 = Doc::new(&pki).sign1(&pki.leaf_key, iana::Algorithm::ES384);
    sign1.signature[10] ^= 0x01;
    expect_err(&pki.verifier(), &sign1.to_vec().unwrap(), "signature").await;
}

#[tokio::test]
async fn refuses_a_tampered_payload() {
    let pki = Pki::new();
    let mut sign1 = Doc::new(&pki).sign1(&pki.leaf_key, iana::Algorithm::ES384);
    // Swap in a payload with a different PCR0, keeping the original signature.
    let mut other = Doc::new(&pki);
    other.pcrs[0] = (0, pcr(0xee));
    sign1.payload = Some(other.payload());
    expect_err(&pki.verifier(), &sign1.to_vec().unwrap(), "signature").await;
}

#[tokio::test]
async fn refuses_a_document_signed_by_a_key_other_than_the_leaf() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&p384_key(), iana::Algorithm::ES384);
    expect_err(&pki.verifier(), &doc, "signature").await;
}

#[tokio::test]
async fn refuses_an_algorithm_other_than_es384() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES256);
    expect_err(&pki.verifier(), &doc, "ES384").await;
}

#[tokio::test]
async fn refuses_a_chain_to_another_root() {
    // A complete, internally valid chain whose root is not the pinned one.
    let pki = Pki::new();
    let other = Pki::new();
    let doc = Doc::new(&other).sign(&other.leaf_key, iana::Algorithm::ES384);
    expect_err(&pki.verifier(), &doc, "root").await;
}

#[tokio::test]
async fn refuses_a_cabundle_that_does_not_start_with_the_pinned_root() {
    // The leaf still chains to the pinned root through the intermediate, but
    // cabundle[0] names another root: the bundle is malformed.
    let pki = Pki::new();
    let other = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.cabundle[0] = other.root.to_der().unwrap();
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "cabundle does not start",
    )
    .await;
}

#[tokio::test]
async fn refuses_a_leaf_not_issued_by_the_bundle() {
    // The bundle names the pinned root, but the leaf comes from another CA.
    let pki = Pki::new();
    let other = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.certificate = other.leaf.to_der().unwrap();
    let doc = doc.sign(&other.leaf_key, iana::Algorithm::ES384);
    expect_err(&pki.verifier(), &doc, "certificate chain").await;
}

#[tokio::test]
async fn refuses_an_empty_cabundle() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.cabundle.clear();
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "cabundle",
    )
    .await;
}

#[tokio::test]
async fn refuses_an_expired_leaf() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);
    let late =
        NitroEnclave::with_trust_anchor(pki.root.to_der().unwrap(), Some(NOW + 3 * HOUR)).unwrap();
    expect_err(&late, &doc, "certificate chain").await;
}

#[tokio::test]
async fn refuses_a_report_data_mismatch() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);
    let err = evaluate(
        &pki.verifier(),
        &doc,
        &ReportData::Value(&[0x33; 48]),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("nonce"), "{err:#}");
}

#[tokio::test]
async fn refuses_report_data_that_only_matches_a_prefix() {
    // No padding or truncation: a 64-byte expectation sharing the 48-byte nonce as prefix fails.
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);
    let mut longer = REPORT_DATA.to_vec();
    longer.extend([0u8; 16]);
    let err = evaluate(
        &pki.verifier(),
        &doc,
        &ReportData::Value(&longer),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("nonce"), "{err:#}");
}

#[tokio::test]
async fn refuses_a_missing_nonce_when_report_data_is_expected() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.nonce = None;
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "nonce",
    )
    .await;
}

#[tokio::test]
async fn refuses_an_init_data_mismatch() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);
    let err = evaluate(
        &pki.verifier(),
        &doc,
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&[0x44; 32]),
    )
    .await
    .unwrap_err();
    assert!(format!("{err:#}").contains("user_data"), "{err:#}");
}

#[tokio::test]
async fn refuses_a_missing_user_data_when_init_data_is_expected() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.user_data = None;
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "user_data",
    )
    .await;
}

#[tokio::test]
async fn refuses_a_digest_other_than_sha384() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.digest = Value::Text("SHA256".into());
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "SHA384",
    )
    .await;
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[tokio::test]
async fn refuses_debug_mode_zero_pcrs(#[case] index: usize) {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.pcrs[index].1 = vec![0u8; 48];
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "debug",
    )
    .await;
}

#[tokio::test]
async fn accepts_an_all_zero_pcr8_for_an_unsigned_image() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.pcrs[5].1 = vec![0u8; 48];
    evaluate(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();
}

#[rstest]
#[case(0)]
#[case(1)]
#[case(2)]
#[tokio::test]
async fn refuses_a_missing_boot_pcr(#[case] index: u64) {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.pcrs.retain(|(i, _)| *i != index);
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        &format!("PCR{index}"),
    )
    .await;
}

#[tokio::test]
async fn refuses_a_pcr_that_is_not_48_bytes() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.pcrs[1].1 = vec![0xa1; 32];
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "48 bytes",
    )
    .await;
}

#[tokio::test]
async fn refuses_a_missing_module_id() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.module_id = Value::Null;
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "module_id",
    )
    .await;
}

#[tokio::test]
async fn refuses_an_unknown_evidence_version() {
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);
    let mut ev = evidence(&doc);
    ev["version"] = json!(2);
    let err = pki
        .verifier()
        .evaluate(ev, &ReportData::NotProvided, &InitDataHash::NotProvided)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("version"), "{err:#}");
}

#[tokio::test]
async fn refuses_garbage_instead_of_cose() {
    let pki = Pki::new();
    expect_err(&pki.verifier(), b"not cbor at all", "COSE_Sign1").await;
}

#[tokio::test]
async fn refuses_a_signing_certificate_that_is_not_p384() {
    // A properly chained leaf, but for a P-256 key: ES384 requires P-384.
    let pki = Pki::new();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let p256 = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
    let leaf = cert(
        "test.enclave",
        &p256,
        Some((&pki.intermediate, &pki.intermediate_key)),
        false,
        NOW - HOUR,
        NOW + HOUR,
    );
    let mut doc = Doc::new(&pki);
    doc.certificate = leaf.to_der().unwrap();
    expect_err(
        &pki.verifier(),
        &doc.sign(&p256, iana::Algorithm::ES384),
        "P-384",
    )
    .await;
}

#[tokio::test]
async fn to_verifier_returns_the_aws_pinned_verifier_for_the_tee() {
    // The verifier the AS builds for the TEE trusts only the AWS root, so a
    // document chained to any other root is refused.
    let storage =
        key_value_storage::KvStorageProvider::new(key_value_storage::StorageBackendConfig {
            storage_type: key_value_storage::KeyValueStorageType::Memory,
            backends: Default::default(),
        });
    let verifier = crate::to_verifier(&kbs_types::Tee::AwsNitroEnclave, None, storage)
        .await
        .unwrap();
    let pki = Pki::new();
    let doc = Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384);
    let err = verifier
        .evaluate(
            evidence(&doc),
            &ReportData::NotProvided,
            &InitDataHash::NotProvided,
        )
        .await
        .unwrap_err();
    assert!(
        format!("{err:#}").contains("pinned AWS Nitro Enclaves root"),
        "{err:#}"
    );
}

fn signed_with_payload(
    pki: &Pki,
    payload: Vec<u8>,
    protected: coset::Header,
    unprotected: coset::Header,
) -> Vec<u8> {
    CoseSign1Builder::new()
        .protected(protected)
        .unprotected(unprotected)
        .payload(payload)
        .create_signature(b"", |tbs| raw_es384(&pki.leaf_key, tbs))
        .build()
        .to_vec()
        .unwrap()
}

#[tokio::test]
async fn refuses_es384_named_only_in_the_unprotected_header() {
    // Only the protected header is signed; an `alg` outside it proves nothing.
    let pki = Pki::new();
    let doc = signed_with_payload(
        &pki,
        Doc::new(&pki).payload(),
        HeaderBuilder::new().build(),
        HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build(),
    );
    expect_err(&pki.verifier(), &doc, "ES384").await;
}

#[tokio::test]
async fn refuses_a_detached_payload() {
    let pki = Pki::new();
    let mut sign1 = Doc::new(&pki).sign1(&pki.leaf_key, iana::Algorithm::ES384);
    sign1.payload = None;
    expect_err(&pki.verifier(), &sign1.to_vec().unwrap(), "no payload").await;
}

#[tokio::test]
async fn refuses_a_payload_that_is_not_a_map() {
    let pki = Pki::new();
    let mut payload = vec![];
    coset::cbor::ser::into_writer(&Value::Array(vec![]), &mut payload).unwrap();
    let doc = signed_with_payload(
        &pki,
        payload,
        HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .build(),
        HeaderBuilder::new().build(),
    );
    expect_err(&pki.verifier(), &doc, "not a CBOR map").await;
}

#[rstest]
#[case("certificate", Value::Null, "`certificate` is missing")]
#[case("certificate", Value::Text("pem".into()), "`certificate` is not a byte string")]
#[case("cabundle", Value::Array(vec![Value::Integer(1.into())]), "non-byte-string")]
#[case("timestamp", Value::Text("now".into()), "`timestamp`")]
#[case("pcrs", Value::Array(vec![]), "`pcrs`")]
#[case("nonce", Value::Text("abc".into()), "`nonce` is not a byte string")]
#[tokio::test]
async fn refuses_a_wrongly_typed_field(
    #[case] field: &'static str,
    #[case] value: Value,
    #[case] needle: &str,
) {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.overrides.push((field, value));
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        needle,
    )
    .await;
}

#[tokio::test]
async fn refuses_duplicate_pcr_indices() {
    // A second, all-zero PCR0 must not hide behind the first.
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.pcrs.push((0, vec![0u8; 48]));
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "PCR0 appears more than once",
    )
    .await;
}

#[tokio::test]
async fn refuses_an_issuer_that_is_not_a_ca() {
    // root -> intermediate -> end-entity "issuer" -> leaf: the end entity
    // (basicConstraints CA:FALSE) cannot issue certificates.
    let pki = Pki::new();
    let fake_issuer_key = p384_key();
    let fake_issuer = cert(
        "test.not-a-ca",
        &fake_issuer_key,
        Some((&pki.intermediate, &pki.intermediate_key)),
        false,
        NOW - HOUR,
        NOW + HOUR,
    );
    let leaf_key = p384_key();
    let leaf = cert(
        "test.enclave",
        &leaf_key,
        Some((&fake_issuer, &fake_issuer_key)),
        false,
        NOW - HOUR,
        NOW + HOUR,
    );
    let mut doc = Doc::new(&pki);
    doc.certificate = leaf.to_der().unwrap();
    doc.cabundle.push(fake_issuer.to_der().unwrap());
    expect_err(
        &pki.verifier(),
        &doc.sign(&leaf_key, iana::Algorithm::ES384),
        "certificate chain",
    )
    .await;
}

#[tokio::test]
async fn refuses_an_oversized_cabundle() {
    // Nine entries: one over the limit.
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    let intermediate = pki.intermediate.to_der().unwrap();
    doc.cabundle.extend(std::iter::repeat_n(intermediate, 7));
    assert_eq!(doc.cabundle.len(), MAX_CABUNDLE_LEN + 1);
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "cabundle has 9 entries",
    )
    .await;
}

#[tokio::test]
async fn accepts_a_cabundle_at_the_limit() {
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    let intermediate = pki.intermediate.to_der().unwrap();
    doc.cabundle.extend(std::iter::repeat_n(intermediate, 6));
    assert_eq!(doc.cabundle.len(), MAX_CABUNDLE_LEN);
    evaluate(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn accepts_a_chain_checked_at_the_current_time() {
    // The production path: no pinned verification time.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let pki = Pki::at(now);
    let verifier = NitroEnclave::with_trust_anchor(pki.root.to_der().unwrap(), None).unwrap();
    evaluate(
        &verifier,
        &Doc::new(&pki).sign(&pki.leaf_key, iana::Algorithm::ES384),
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();
}

/// A certificate issued by the PKI's intermediate with the given extensions only.
fn leaf_with_extensions(
    pki: &Pki,
    key: &PKey<Private>,
    extensions: Vec<openssl::x509::X509Extension>,
) -> X509 {
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "test.enclave").unwrap();
    let name = name.build();
    let mut b = X509Builder::new().unwrap();
    b.set_version(2).unwrap();
    b.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap())
        .unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(pki.intermediate.subject_name()).unwrap();
    b.set_pubkey(key).unwrap();
    b.set_not_before(&Asn1Time::from_unix(NOW - HOUR).unwrap())
        .unwrap();
    b.set_not_after(&Asn1Time::from_unix(NOW + HOUR).unwrap())
        .unwrap();
    for extension in extensions {
        b.append_extension(extension).unwrap();
    }
    b.sign(&pki.intermediate_key, MessageDigest::sha384())
        .unwrap();
    b.build()
}

#[tokio::test]
async fn refuses_a_ca_certificate_as_the_signer() {
    // The intermediate chains to the root, but a CA does not sign documents.
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.certificate = pki.intermediate.to_der().unwrap();
    doc.cabundle = vec![pki.root.to_der().unwrap()];
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.intermediate_key, iana::Algorithm::ES384),
        "signing certificate is a CA",
    )
    .await;
}

#[rstest]
#[case::key_agreement_only(true)]
#[case::no_key_usage(false)]
#[tokio::test]
async fn refuses_a_signer_without_digital_signature_key_usage(#[case] with_key_usage: bool) {
    let pki = Pki::new();
    let key = p384_key();
    let mut extensions = vec![BasicConstraints::new().critical().build().unwrap()];
    if with_key_usage {
        extensions.push(KeyUsage::new().key_agreement().build().unwrap());
    }
    let leaf = leaf_with_extensions(&pki, &key, extensions);
    let mut doc = Doc::new(&pki);
    doc.certificate = leaf.to_der().unwrap();
    expect_err(
        &pki.verifier(),
        &doc.sign(&key, iana::Algorithm::ES384),
        "digitalSignature",
    )
    .await;
}

#[tokio::test]
async fn accepts_a_signer_shaped_like_the_aws_leaf() {
    // AWS leaves: CA:FALSE (critical), keyUsage digitalSignature +
    // nonRepudiation (not critical).
    let pki = Pki::new();
    let key = p384_key();
    let leaf = leaf_with_extensions(
        &pki,
        &key,
        vec![
            BasicConstraints::new().critical().build().unwrap(),
            KeyUsage::new()
                .digital_signature()
                .non_repudiation()
                .build()
                .unwrap(),
        ],
    );
    let mut doc = Doc::new(&pki);
    doc.certificate = leaf.to_der().unwrap();
    evaluate(
        &pki.verifier(),
        &doc.sign(&key, iana::Algorithm::ES384),
        &ReportData::Value(&REPORT_DATA),
        &InitDataHash::Value(&INIT_DATA_DIGEST),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn refuses_a_critical_header_parameter() {
    // RFC 9052: a recipient that does not understand a `crit` label must fail.
    let pki = Pki::new();
    let doc = signed_with_payload(
        &pki,
        Doc::new(&pki).payload(),
        HeaderBuilder::new()
            .algorithm(iana::Algorithm::ES384)
            .add_critical(iana::HeaderParameter::ContentType)
            .build(),
        HeaderBuilder::new().build(),
    );
    expect_err(&pki.verifier(), &doc, "critical header").await;
}

/// The payload of `Doc::new`, decoded, edited by `edit` and re-encoded.
fn edited_payload(pki: &Pki, edit: impl FnOnce(&mut Vec<(Value, Value)>)) -> Vec<u8> {
    let payload = Doc::new(pki).payload();
    let Value::Map(mut entries) = coset::cbor::de::from_reader(payload.as_slice()).unwrap() else {
        unreachable!()
    };
    edit(&mut entries);
    let mut out = vec![];
    coset::cbor::ser::into_writer(&Value::Map(entries), &mut out).unwrap();
    out
}

fn es384_protected() -> coset::Header {
    HeaderBuilder::new()
        .algorithm(iana::Algorithm::ES384)
        .build()
}

#[rstest]
#[case::nonce("nonce")]
#[case::user_data("user_data")]
#[case::pcrs("pcrs")]
#[tokio::test]
async fn refuses_a_payload_key_that_appears_twice(#[case] key: &str) {
    // Whichever copy a reader picks, the document is ambiguous.
    let pki = Pki::new();
    let payload = edited_payload(&pki, |entries| {
        let first = entries
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .unwrap()
            .clone();
        entries.insert(0, first);
    });
    let doc = signed_with_payload(
        &pki,
        payload,
        es384_protected(),
        HeaderBuilder::new().build(),
    );
    expect_err(
        &pki.verifier(),
        &doc,
        &format!("`{key}` appears more than once"),
    )
    .await;
}

#[tokio::test]
async fn refuses_a_payload_key_that_is_not_text() {
    let pki = Pki::new();
    let payload = edited_payload(&pki, |entries| {
        entries.push((Value::Integer(1.into()), Value::Text("x".into())));
    });
    let doc = signed_with_payload(
        &pki,
        payload,
        es384_protected(),
        HeaderBuilder::new().build(),
    );
    expect_err(&pki.verifier(), &doc, "payload key is not text").await;
}

#[tokio::test]
async fn refuses_trailing_bytes_after_the_payload() {
    let pki = Pki::new();
    let mut payload = Doc::new(&pki).payload();
    payload.push(0x00);
    let doc = signed_with_payload(
        &pki,
        payload,
        es384_protected(),
        HeaderBuilder::new().build(),
    );
    expect_err(&pki.verifier(), &doc, "trailing bytes").await;
}

#[tokio::test]
async fn bounds_the_cabundle_before_parsing_any_certificate() {
    // Nothing in the document is authenticated yet: the size check comes first.
    let pki = Pki::new();
    let mut doc = Doc::new(&pki);
    doc.certificate = b"not a certificate".to_vec();
    let intermediate = pki.intermediate.to_der().unwrap();
    doc.cabundle.extend(std::iter::repeat_n(intermediate, 8));
    expect_err(
        &pki.verifier(),
        &doc.sign(&pki.leaf_key, iana::Algorithm::ES384),
        "cabundle has",
    )
    .await;
}

/// A real attestation document, taken from a production-mode enclave
/// (unsigned EIF, `ttrpc-aa --initdata-toml`) on an m7g instance in us-east-2,
/// signed by the AWS PKI. Its leaf is valid from 1795150868 to 1795161671.
mod real_document {
    use super::*;

    const EVIDENCE: &str = include_str!("testdata/aws_attestation_document.json");
    /// The document's own timestamp, in seconds.
    const ISSUED_AT: i64 = 1_795_151_059;
    const LEAF_NOT_AFTER: i64 = 1_795_161_671;
    const REPORT_DATA: [u8; 48] = [0; 48];
    const INIT_DATA_DIGEST: &str =
        "dc647d7ca3ab67688d291b090ffe69881c273464a10937232e2e222c8d6bd0d6";
    const PCR0: &str = "0d7554adabb5288c8b6260fd6e405da1a1ae0e1390ac91590376070feaac93a7e2f46ee6614f51ea347a6838687589c8";

    fn verifier_at(at: i64) -> NitroEnclave {
        NitroEnclave {
            at: Some(at),
            ..NitroEnclave::default()
        }
    }

    fn document() -> Vec<u8> {
        let evidence: serde_json::Value = serde_json::from_str(EVIDENCE).unwrap();
        base64::engine::general_purpose::STANDARD
            .decode(evidence["attestation_document"].as_str().unwrap())
            .unwrap()
    }

    async fn verify(
        at: i64,
        document: &[u8],
        report_data: &[u8],
    ) -> anyhow::Result<serde_json::Value> {
        let init_data = hex::decode(INIT_DATA_DIGEST).unwrap();
        evaluate(
            &verifier_at(at),
            document,
            &ReportData::Value(report_data),
            &InitDataHash::Value(&init_data),
        )
        .await
    }

    #[tokio::test]
    async fn accepts_it_against_the_aws_root() {
        let claims = verify(ISSUED_AT, &document(), &REPORT_DATA).await.unwrap();
        assert_eq!(
            claims["module_id"],
            "i-08b8fd8959db11fa3-enc01a1f754252f597f"
        );
        assert_eq!(claims["timestamp"], 1_795_151_059_484u64);
        assert_eq!(claims["pcr0"], PCR0);
        assert_eq!(claims["pcr8"], hex::encode([0u8; 48]));
        assert_eq!(claims["report_data"], hex::encode(REPORT_DATA));
        assert_eq!(claims["init_data"], INIT_DATA_DIGEST);
        assert!(claims.get("public_key").is_none());
    }

    #[tokio::test]
    async fn refuses_it_once_its_leaf_has_expired() {
        let err = verify(LEAF_NOT_AFTER + 1, &document(), &REPORT_DATA)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("certificate has expired"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn refuses_it_with_a_flipped_pcr0_byte() {
        let mut document = document();
        let pcr0 = hex::decode(PCR0).unwrap();
        let at = document
            .windows(pcr0.len())
            .position(|w| w == pcr0.as_slice())
            .unwrap();
        document[at] ^= 1;
        let err = verify(ISSUED_AT, &document, &REPORT_DATA)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("signature does not verify"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn refuses_it_for_another_session() {
        let err = verify(ISSUED_AT, &document(), &[1; 48]).await.unwrap_err();
        assert!(format!("{err:#}").contains("`nonce`"), "{err:#}");
    }
}

#[test]
fn the_default_verifier_pins_the_aws_nitro_enclaves_root_g1() {
    // Fingerprint published at docs.aws.amazon.com/enclaves/latest/user/verify-root.html
    let fingerprint = NitroEnclave::default().trust_anchor_sha256();
    assert_eq!(
        hex::encode_upper(fingerprint),
        "641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B"
    );
}
