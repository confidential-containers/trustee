// Copyright (c) 2026 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! DICE certificate chain data structures and X.509 DER parsing.
//!
//! Based on TCG DICE Architecture Specification.
//! DICE chain: Root CA → DeviceID cert → Alias cert
//! Each layer carries FWID (Firmware ID) measurements.
//!
//! Certificates are DER-encoded X.509 as read from sysfs on the attester side.
//! The `from_der()` constructors parse X.509 fields into our domain structs,
//! caching the raw TBS (to-be-signed) bytes for signature verification.

use anyhow::{bail, Result};
use p384::elliptic_curve::sec1::FromEncodedPoint;
use p384::PublicKey;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

/// TCG DICE TcbInfo extension OID: 2.23.133.5.4.1
const TCG_DICE_TCB_INFO_OID: &[u64] = &[2, 23, 133, 5, 4, 1];

/// A firmware layer in the DICE measurement chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FirmwareLayer {
    /// Layer name (e.g., "bootloader", "firmware", "OS").
    /// Note: not included in TBS data — informational only, not integrity-protected.
    pub name: String,
    /// SHA-384 hash of the firmware image
    pub fwid: Vec<u8>,
    /// Version string.
    /// Note: not included in TBS data — informational only, not integrity-protected.
    pub version: String,
}

/// DeviceID certificate (first in the DICE chain).
#[derive(Debug, Clone)]
pub struct DeviceIdCert {
    /// Device serial number (manufacturer-assigned)
    pub serial: String,
    /// Device class identifier (e.g., "bluefield3")
    pub device_class: String,
    /// Firmware measurement layers (ordered, from boot ROM to final layer)
    pub firmware_layers: Vec<FirmwareLayer>,
    /// DeviceID public key (P-384 ECDSA)
    pub public_key: PublicKey,
    /// Manufacturer Root CA signature over the cert TBS data (DER-encoded ECDSA)
    pub root_ca_signature: Vec<u8>,
    /// Certificate validity: not-before (Unix timestamp)
    pub not_before: u64,
    /// Certificate validity: not-after (Unix timestamp)
    pub not_after: u64,
    /// Raw TBS (to-be-signed) DER bytes from X.509 parsing, for signature verification.
    pub tbs_raw: Vec<u8>,
}

impl DeviceIdCert {
    /// Parses a DeviceID certificate from DER-encoded X.509.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("Failed to parse DeviceID X.509 DER: {:?}", e))?;

        let tbs_raw = cert.tbs_certificate.as_ref().to_vec();
        let serial = cert.tbs_certificate.serial.to_str_radix(16);
        let device_class = extract_cn(&cert).unwrap_or_else(|_| "unknown".to_string());
        let public_key = extract_p384_pubkey(&cert)?;

        let not_before: u64 = cert
            .validity()
            .not_before
            .timestamp()
            .try_into()
            .unwrap_or(0u64);
        let not_after: u64 = cert
            .validity()
            .not_after
            .timestamp()
            .try_into()
            .unwrap_or(0u64);

        let root_ca_signature = cert.signature_value.data.to_vec();

        // Best-effort TCG DICE TcbInfo extension parsing
        let firmware_layers = extract_firmware_layers(&cert);

        Ok(Self {
            serial,
            device_class,
            firmware_layers,
            public_key,
            root_ca_signature,
            not_before,
            not_after,
            tbs_raw,
        })
    }

    /// Returns the accumulated FWID (hash of all layer FWIDs).
    pub fn accumulated_fwid(&self) -> Vec<u8> {
        use sha2::{Digest, Sha384};
        let mut hasher = Sha384::new();
        for layer in &self.firmware_layers {
            hasher.update(&layer.fwid);
        }
        hasher.finalize().to_vec()
    }

    /// Checks certificate temporal validity.
    pub fn is_valid_at(&self, now: u64) -> bool {
        now >= self.not_before && now <= self.not_after
    }
}

/// Alias certificate (second in the DICE chain, leaf cert).
#[derive(Debug, Clone)]
pub struct AliasCert {
    /// Alias certificate serial (per-session)
    pub serial: String,
    /// Alias public key (P-384 ECDSA)
    pub public_key: PublicKey,
    /// Timestamp when Alias cert was generated (notBefore as Unix timestamp)
    pub timestamp: u64,
    /// DeviceID signature over the Alias cert TBS data (DER-encoded ECDSA)
    pub device_id_signature: Vec<u8>,
    /// Raw TBS (to-be-signed) DER bytes from X.509 parsing, for signature verification.
    pub tbs_raw: Vec<u8>,
}

impl AliasCert {
    /// Parses an Alias certificate from DER-encoded X.509.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|e| anyhow::anyhow!("Failed to parse Alias X.509 DER: {:?}", e))?;

        let tbs_raw = cert.tbs_certificate.as_ref().to_vec();
        let serial = cert.tbs_certificate.serial.to_str_radix(16);
        let public_key = extract_p384_pubkey(&cert)?;

        let timestamp: u64 = cert
            .validity()
            .not_before
            .timestamp()
            .try_into()
            .unwrap_or(0u64);

        let device_id_signature = cert.signature_value.data.to_vec();

        Ok(Self {
            serial,
            public_key,
            timestamp,
            device_id_signature,
            tbs_raw,
        })
    }
}

/// Complete DICE certificate chain from the DPU.
#[derive(Debug, Clone)]
pub struct DiceCertChain {
    /// DeviceID certificate (signed by Root CA)
    pub device_id_cert: DeviceIdCert,
    /// Alias certificate (signed by DeviceID key)
    pub alias_cert: AliasCert,
}

/// Extracts P-384 public key from X.509 SubjectPublicKeyInfo.
pub(super) fn extract_p384_pubkey(cert: &X509Certificate) -> Result<PublicKey> {
    let spki = &cert.tbs_certificate.subject_pki;
    let key_bytes = spki.subject_public_key.data.as_ref();
    let point = p384::EncodedPoint::from_bytes(key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid SEC1 P-384 point in X.509: {}", e))?;
    PublicKey::from_encoded_point(&point)
        .into_option()
        .ok_or_else(|| anyhow::anyhow!("Invalid P-384 public key in X.509 SubjectPublicKeyInfo"))
}

/// Extracts Common Name from X.509 Subject.
fn extract_cn(cert: &X509Certificate) -> Result<String> {
    for rdn in cert.subject().iter() {
        for attr in rdn.iter() {
            if attr.attr_type() == &oid_registry::OID_X509_COMMON_NAME {
                return attr
                    .as_str()
                    .map(|s| s.to_string())
                    .map_err(|e| anyhow::anyhow!("CN is not valid UTF-8: {:?}", e));
            }
        }
    }
    bail!("No CN found in X.509 Subject")
}

/// Extracts firmware layers from TCG DICE TcbInfo extension (OID 2.23.133.5.4.1).
/// Returns empty Vec if extension is not present (expected for non-DICE certs).
fn extract_firmware_layers(cert: &X509Certificate) -> Vec<FirmwareLayer> {
    let tcb_info_oid =
        x509_parser::oid_registry::Oid::from(TCG_DICE_TCB_INFO_OID).expect("valid OID");

    cert.extensions()
        .iter()
        .find(|ext| ext.oid == tcb_info_oid)
        .and_then(|ext| parse_tcb_info_fwids(ext.value).ok())
        .unwrap_or_default()
}

/// Parses FWID entries from a TcbInfo DER extension value.
///
/// TcbInfo ::= SEQUENCE {
///     vendor [0] IMPLICIT UTF8String OPTIONAL,
///     model [1] IMPLICIT UTF8String OPTIONAL,
///     version [2] IMPLICIT UTF8String OPTIONAL,
///     svn [3] IMPLICIT INTEGER OPTIONAL,
///     layer [4] IMPLICIT INTEGER OPTIONAL,
///     index [5] IMPLICIT INTEGER OPTIONAL,
///     fwids [6] IMPLICIT SEQUENCE OF FWID OPTIONAL,
///     ...
/// }
/// FWID ::= SEQUENCE { hashAlg OBJECT IDENTIFIER, digest OCTET STRING }
fn parse_tcb_info_fwids(ext_value: &[u8]) -> Result<Vec<FirmwareLayer>> {
    let mut layers = Vec::new();

    // Parse outer SEQUENCE (TcbInfo)
    let (_, tcb_info) = parse_der_sequence(ext_value)?;

    // Look for context-tagged [6] (fwids) in the TcbInfo SEQUENCE items
    for item in tcb_info.ref_iter() {
        // Context tag [6] = class CONTEXT (0x80) | constructed (0x20) | tag 6 = 0xA6
        if item.header.raw_tag() == Some(&[0xA6]) {
            // The content is a SEQUENCE OF FWID
            let inner = item.content.as_slice()?;
            let (_, fwids_seq) = parse_der_sequence(inner)?;

            for (layer_idx, fwid_entry) in fwids_seq.ref_iter().enumerate() {
                if let Ok(fwid_items) = fwid_entry.as_sequence() {
                    // FWID ::= SEQUENCE { hashAlg OID, digest OCTET STRING }
                    if fwid_items.len() >= 2 {
                        let digest = fwid_items[1].content.as_slice().unwrap_or(&[]).to_vec();
                        layers.push(FirmwareLayer {
                            name: format!("layer_{}", layer_idx),
                            fwid: digest,
                            version: String::new(),
                        });
                    }
                }
            }
            break;
        }
    }

    Ok(layers)
}

/// Helper: parse a DER SEQUENCE from raw bytes.
fn parse_der_sequence(data: &[u8]) -> Result<(&[u8], x509_parser::der_parser::ber::BerObject<'_>)> {
    x509_parser::der_parser::der::parse_der_sequence(data)
        .map_err(|e| anyhow::anyhow!("DER SEQUENCE parse error: {:?}", e))
}
