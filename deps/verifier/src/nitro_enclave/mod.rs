// Copyright (c) 2026 XHawk Corp
// SPDX-License-Identifier: Apache-2.0

//! AWS Nitro Enclaves verifier.
//!
//! An enclave attests with an *attestation document* issued by the Nitro
//! Secure Module (NSM): a COSE_Sign1 signed ES384 by a short-lived leaf
//! certificate whose `cabundle` chains to the AWS Nitro Enclaves Root (G1).
//! See <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>.
//!
//! Binding to the KBS protocol:
//! - `report_data` (the hash of the RCAR `runtime_data`) is carried in the
//!   document's `nonce`;
//! - the InitData digest is carried in `user_data`. Nitro has no host-set
//!   register like SNP `HOST_DATA`, so this binding trusts the measured image
//!   (PCR0) that sets it, not the hardware.
//!
//! Both are compared exactly, without padding or truncation.

use anyhow::{Context, Result, anyhow, bail, ensure};
use async_trait::async_trait;
use base64::Engine;
use coset::cbor::value::Value;
use coset::{
    CborSerializable, CoseSign1, RegisteredLabelWithPrivate, TaggedCborSerializable, iana,
};
use openssl::bn::BigNum;
use openssl::ecdsa::EcdsaSig;
use openssl::hash::{MessageDigest, hash};
use openssl::nid::Nid;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::verify::X509VerifyParam;
use openssl::x509::{X509, X509StoreContext};
use serde::Deserialize;
use serde_json::json;
use tracing::debug;

use super::{InitDataHash, ReportData, TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};

/// The AWS Nitro Enclaves Root (G1), SHA-256 fingerprint
/// `641A0321A3E244EFE456463195D606317ED7CDCC3C1756E09893F3C68F79BB5B`.
const AWS_NITRO_ENCLAVES_ROOT_G1: &[u8] = include_bytes!("aws_nitro_enclaves_root_g1.pem");

/// The only evidence format version this verifier understands.
const EVIDENCE_VERSION: u32 = 1;

/// SHA-384 PCRs are 48 bytes.
const PCR_LEN: usize = 48;

/// PCRs a debug-mode enclave reports as all zeros, and which must be present.
const BOOT_PCRS: [u64; 3] = [0, 1, 2];

/// PCRs reported as claims: the image, kernel and bootstrap, application, and
/// the EIF signing certificate. PCR3 (parent IAM role) and PCR4 (parent
/// instance ID) describe the host, not the workload.
const REPORTED_PCRS: [u64; 4] = [0, 1, 2, 8];

/// ES384 signatures in COSE are raw `r || s`, 48 bytes each.
const ES384_SIGNATURE_LEN: usize = 96;

/// AWS bundles hold the root and a few intermediates (four entries today).
const MAX_CABUNDLE_LEN: usize = 8;

#[derive(Deserialize)]
struct NitroEnclaveEvidence {
    version: u32,
    /// Standard base64 of the COSE_Sign1 bytes returned by the NSM.
    attestation_document: String,
}

#[derive(Debug)]
pub struct NitroEnclave {
    trust_anchor: X509,
    /// Verification time (Unix seconds). `None` means the current time; only
    /// tests pin it, since leaf certificates live for hours.
    at: Option<i64>,
}

impl Default for NitroEnclave {
    fn default() -> Self {
        Self {
            trust_anchor: X509::from_pem(AWS_NITRO_ENCLAVES_ROOT_G1)
                .expect("the embedded AWS Nitro Enclaves root is a valid PEM certificate"),
            at: None,
        }
    }
}

impl NitroEnclave {
    #[cfg(test)]
    fn with_trust_anchor(root_der: Vec<u8>, at: Option<i64>) -> Result<Self> {
        Ok(Self {
            trust_anchor: X509::from_der(&root_der)?,
            at,
        })
    }

    #[cfg(test)]
    fn trust_anchor_sha256(&self) -> Vec<u8> {
        self.trust_anchor
            .digest(MessageDigest::sha256())
            .expect("digest of the trust anchor")
            .to_vec()
    }

    /// Verify `leaf` up to the pinned root through the intermediates of
    /// `cabundle` (`[root, intermediate_1, ..., intermediate_n]`).
    fn verify_chain(&self, leaf: &X509, cabundle: &[Vec<u8>]) -> Result<()> {
        let (bundle_root, intermediates) = cabundle.split_first().context("cabundle is empty")?;
        ensure!(
            *bundle_root == self.trust_anchor.to_der()?,
            "cabundle does not start with the pinned AWS Nitro Enclaves root"
        );

        let mut store = X509StoreBuilder::new()?;
        store.add_cert(self.trust_anchor.clone())?;
        if let Some(at) = self.at {
            let mut param = X509VerifyParam::new()?;
            param.set_time(at as _);
            store.set_param(&param)?;
        }
        let store = store.build();

        let mut chain = Stack::new()?;
        for der in intermediates {
            chain.push(X509::from_der(der).context("cabundle holds an invalid certificate")?)?;
        }

        let mut ctx = X509StoreContext::new()?;
        let verified = ctx.init(&store, leaf, &chain, |c| {
            let ok = c.verify_cert()?;
            Ok((ok, c.error()))
        })?;
        match verified {
            (true, _) => Ok(()),
            (false, error) => {
                bail!("certificate chain does not verify to the pinned root: {error}")
            }
        }
    }
}

/// The document signer is an end entity allowed to sign: not a CA, and with a
/// keyUsage that includes digitalSignature, as AWS issues it.
fn check_signer(leaf_der: &[u8]) -> Result<()> {
    let (_, cert) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|e| anyhow!("`certificate` is not a DER certificate: {e}"))?;
    let basic_constraints = cert
        .basic_constraints()
        .map_err(|e| anyhow!("signing certificate basicConstraints: {e}"))?;
    ensure!(
        !basic_constraints.is_some_and(|bc| bc.value.ca),
        "the signing certificate is a CA"
    );
    let key_usage = cert
        .key_usage()
        .map_err(|e| anyhow!("signing certificate keyUsage: {e}"))?;
    ensure!(
        key_usage.is_some_and(|ku| ku.value.digital_signature()),
        "the signing certificate's keyUsage does not allow digitalSignature"
    );
    Ok(())
}

/// Verify the COSE_Sign1 ES384 signature with the leaf certificate's key.
fn verify_signature(sign1: &CoseSign1, leaf: &X509) -> Result<()> {
    let key = leaf
        .public_key()?
        .ec_key()
        .context("the signing certificate does not hold an EC key")?;
    ensure!(
        key.group().curve_name() == Some(Nid::SECP384R1),
        "the signing certificate's key is not P-384"
    );

    sign1.verify_signature(b"", |signature, tbs| -> Result<()> {
        ensure!(
            signature.len() == ES384_SIGNATURE_LEN,
            "ES384 signature must be {ES384_SIGNATURE_LEN} bytes, got {}",
            signature.len()
        );
        let (r, s) = signature.split_at(ES384_SIGNATURE_LEN / 2);
        let sig =
            EcdsaSig::from_private_components(BigNum::from_slice(r)?, BigNum::from_slice(s)?)?;
        let digest = hash(MessageDigest::sha384(), tbs)?;
        ensure!(
            sig.verify(&digest, &key)?,
            "attestation document signature does not verify"
        );
        Ok(())
    })
}

/// The attestation document's CBOR payload, as a map with unique text keys.
struct Payload(Vec<(Value, Value)>);

impl Payload {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let mut rest = bytes;
        let value: Value = coset::cbor::de::from_reader(&mut rest)
            .map_err(|e| anyhow!("payload is not CBOR: {e}"))?;
        ensure!(rest.is_empty(), "payload has {} trailing bytes", rest.len());
        let Value::Map(entries) = value else {
            bail!("payload is not a CBOR map");
        };
        // One reading of the document only: no key may appear twice.
        let mut seen = std::collections::BTreeSet::new();
        for (key, _) in &entries {
            let key = key.as_text().context("a payload key is not text")?;
            ensure!(seen.insert(key), "`{key}` appears more than once");
        }
        Ok(Self(entries))
    }

    /// The value under `key`; `null` counts as absent.
    fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(k, _)| k.as_text() == Some(key))
            .map(|(_, v)| v)
            .filter(|v| !v.is_null())
    }

    fn text(&self, key: &str) -> Result<&str> {
        self.get(key)
            .and_then(Value::as_text)
            .with_context(|| format!("`{key}` is missing or not text"))
    }

    fn bytes(&self, key: &str) -> Result<&[u8]> {
        self.optional_bytes(key)?
            .with_context(|| format!("`{key}` is missing"))
    }

    fn optional_bytes(&self, key: &str) -> Result<Option<&[u8]>> {
        match self.get(key) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            Some(_) => bail!("`{key}` is not a byte string"),
        }
    }

    fn timestamp(&self) -> Result<u64> {
        let value = self
            .get("timestamp")
            .and_then(Value::as_integer)
            .context("`timestamp` is missing or not an integer")?;
        u64::try_from(value).map_err(|_| anyhow!("`timestamp` is out of range"))
    }

    fn cabundle(&self) -> Result<Vec<Vec<u8>>> {
        let entries = self
            .get("cabundle")
            .and_then(Value::as_array)
            .context("`cabundle` is missing or not an array")?;
        // Bounded before any certificate is parsed: the document is not yet authenticated.
        ensure!(
            entries.len() <= MAX_CABUNDLE_LEN,
            "cabundle has {} entries, more than {MAX_CABUNDLE_LEN}",
            entries.len()
        );
        entries
            .iter()
            .map(|e| {
                e.as_bytes()
                    .cloned()
                    .context("cabundle holds a non-byte-string entry")
            })
            .collect()
    }

    /// PCRs by index, each checked to be 48 bytes.
    fn pcrs(&self) -> Result<Vec<(u64, Vec<u8>)>> {
        let entries = self
            .get("pcrs")
            .and_then(Value::as_map)
            .context("`pcrs` is missing or not a map")?;
        let mut seen = std::collections::BTreeSet::new();
        entries
            .iter()
            .map(|(index, value)| {
                let index = index
                    .as_integer()
                    .and_then(|i| u64::try_from(i).ok())
                    .context("a PCR index is not a non-negative integer")?;
                ensure!(seen.insert(index), "PCR{index} appears more than once");
                let value = value
                    .as_bytes()
                    .with_context(|| format!("PCR{index} is not a byte string"))?;
                ensure!(
                    value.len() == PCR_LEN,
                    "PCR{index} is {} bytes, not {PCR_LEN} bytes",
                    value.len()
                );
                Ok((index, value.clone()))
            })
            .collect()
    }
}

fn parse_cose_sign1(document: &[u8]) -> Result<CoseSign1> {
    // The NSM returns the untagged form; accept the tagged form (CBOR tag 18) as well.
    CoseSign1::from_tagged_slice(document)
        .or_else(|_| CoseSign1::from_slice(document))
        .map_err(|e| anyhow!("attestation document is not a COSE_Sign1: {e:?}"))
}

/// Check an attested value against what the caller expects, exactly.
fn check_binding(field: &str, expected: Option<&[u8]>, attested: Option<&[u8]>) -> Result<()> {
    let Some(expected) = expected else {
        return Ok(());
    };
    let attested =
        attested.with_context(|| format!("`{field}` is missing but a value is expected"))?;
    ensure!(
        attested == expected,
        "`{field}` {} does not match the expected {}",
        hex::encode(attested),
        hex::encode(expected)
    );
    Ok(())
}

#[async_trait]
impl Verifier for NitroEnclave {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let evidence: NitroEnclaveEvidence =
            serde_json::from_value(evidence).context("invalid Nitro Enclave evidence")?;
        ensure!(
            evidence.version == EVIDENCE_VERSION,
            "unsupported Nitro Enclave evidence version {} (expected {EVIDENCE_VERSION})",
            evidence.version
        );
        let document = base64::engine::general_purpose::STANDARD
            .decode(&evidence.attestation_document)
            .context("attestation_document is not base64")?;

        // 1. COSE_Sign1, ES384.
        let sign1 = parse_cose_sign1(&document)?;
        ensure!(
            sign1.protected.header.alg
                == Some(RegisteredLabelWithPrivate::Assigned(iana::Algorithm::ES384)),
            "attestation document must be signed with ES384"
        );
        ensure!(
            sign1.protected.header.crit.is_empty(),
            "attestation document has critical header parameters this verifier does not understand"
        );
        let payload = Payload::parse(
            sign1
                .payload
                .as_deref()
                .context("attestation document has no payload")?,
        )?;

        // 2. The signing certificate chains to the pinned root, may sign, and
        //    signed the document.
        let cabundle = payload.cabundle()?;
        let leaf_der = payload.bytes("certificate")?;
        let leaf = X509::from_der(leaf_der).context("`certificate` is not a DER certificate")?;
        self.verify_chain(&leaf, &cabundle)?;
        check_signer(leaf_der)?;
        verify_signature(&sign1, &leaf)?;

        // 3. The signed fields.
        let module_id = payload.text("module_id")?;
        let timestamp = payload.timestamp()?;
        let digest = payload.text("digest")?;
        ensure!(digest == "SHA384", "`digest` must be SHA384, got {digest}");

        let pcrs = payload.pcrs()?;
        let pcr = |index: u64| pcrs.iter().find(|(i, _)| *i == index).map(|(_, v)| v);
        for index in BOOT_PCRS {
            let value = pcr(index).with_context(|| format!("PCR{index} is missing"))?;
            ensure!(
                value.iter().any(|b| *b != 0),
                "PCR{index} is all zeros: the enclave runs in debug mode"
            );
        }

        // 4. The bindings to this KBS session.
        let nonce = payload.optional_bytes("nonce")?;
        let user_data = payload.optional_bytes("user_data")?;
        let expected_report_data = match expected_report_data {
            ReportData::Value(v) => Some(*v),
            ReportData::NotProvided => None,
        };
        let expected_init_data = match expected_init_data_hash {
            InitDataHash::Value(v) => Some(*v),
            InitDataHash::NotProvided => None,
        };
        check_binding("nonce", expected_report_data, nonce)?;
        check_binding("user_data", expected_init_data, user_data)?;

        let mut claims = json!({
            "module_id": module_id,
            "timestamp": timestamp,
            "digest": digest,
            "report_data": hex::encode(nonce.unwrap_or_default()),
            "init_data": hex::encode(user_data.unwrap_or_default()),
        });
        for index in REPORTED_PCRS {
            if let Some(value) = pcr(index) {
                claims[format!("pcr{index}")] = json!(hex::encode(value));
            }
        }
        if let Some(public_key) = payload.optional_bytes("public_key")? {
            claims["public_key"] = json!(hex::encode(public_key));
        }

        debug!("Nitro Enclave attestation document verified for module {module_id}");
        Ok(vec![(claims, "cpu".to_string())])
    }
}

#[cfg(test)]
mod tests;
