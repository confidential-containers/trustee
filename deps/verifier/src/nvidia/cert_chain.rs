// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use asn1_rs::{oid, Any, Class, FromDer, OctetString, Oid, Sequence, Tag};
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::{store::X509StoreBuilder, X509StoreContext, X509};
use std::sync::LazyLock;
use x509_parser::prelude::X509Certificate;

use super::Architecture;

pub struct NvidiaCertificate {
    cert: X509,
    digest: String,
}

static NVIDIA_ROOT_CA: LazyLock<NvidiaCertificate> = LazyLock::new(|| {
    let cert = X509::from_pem(include_bytes!("nvidia_device_root.pem")).unwrap();
    let digest = certificate_fingerprint(&cert).unwrap();
    NvidiaCertificate { cert, digest }
});

/// Certificate chain for a NVIDIA device
///
/// Order of the certificates:
/// First            = Certificate used to verify the attestation report
/// [..]             = Intermediate CAs
/// Second to last   = Device Architecture certificate
/// Last             = Root CA certificate
///
/// Example for a H100 GPU:
/// $ openssl crl2pkcs7 -nocrl -certfile ./hopper_cert_chain_case1.txt | openssl pkcs7 -print_certs -noout
///
/// subject=serialNumber = 53C22BA15E5D68088282DA074ED9FB37AA585771, C = US, O = NVIDIA Corporation, CN = GH100 A01 GSP FMC LF
/// issuer=serialNumber = 41431D480FE5E87274, C = US, O = NVIDIA Corporation, CN = GH100 A01 GSP BROM
///
/// subject=serialNumber = 41431D480FE5E87274, C = US, O = NVIDIA Corporation, CN = GH100 A01 GSP BROM
/// issuer=CN = NVIDIA GH100 Provisioner ICA 1, O = NVIDIA Corporation, C = US
///
/// subject=CN = NVIDIA GH100 Provisioner ICA 1, O = NVIDIA Corporation, C = US
/// issuer=CN = NVIDIA GH100 Identity, O = NVIDIA Corporation
///
/// subject=CN = NVIDIA GH100 Identity, O = NVIDIA Corporation
/// issuer=CN = NVIDIA Device Identity CA, O = NVIDIA
///
/// subject=CN = NVIDIA Device Identity CA, O = NVIDIA
/// issuer=CN = NVIDIA Device Identity CA, O = NVIDIA
#[derive(Debug, Default)]
pub struct NvidiaCertificateChain {
    certs: Vec<X509>,
}

impl NvidiaCertificateChain {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let certs = X509::stack_from_pem(bytes)?;
        Ok(Self { certs })
    }

    pub fn check_root_ca_is_trusted(&self) -> Result<()> {
        let root_ca = self.get_root_certificate()?;
        let digest = certificate_fingerprint(root_ca)?;

        if digest != NVIDIA_ROOT_CA.digest {
            bail!("Root CA in the certificate chain is not trusted");
        }
        Ok(())
    }

    pub fn get_root_certificate(&self) -> Result<&X509> {
        self.certs.last().ok_or(anyhow!(
            "Root CA certificate not found in the NVIDIA certificate chain"
        ))
    }

    pub fn get_leaf_certificate(&self) -> Result<&X509> {
        self.certs.first().ok_or(anyhow!(
            "Leaf certificate not found in the NVIDIA certificate chain"
        ))
    }

    /// NVIDIA's local verifier uses the leaf certificate serial as the UEID.
    /// It is certificate-bound, unlike the UUID metadata supplied by the guest.
    /// <https://github.com/NVIDIA/nvtrust/blob/2026.06.04.001/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin.py#L400-L405>
    pub(crate) fn ueid(&self) -> Result<String> {
        Ok(self
            .get_leaf_certificate()?
            .serial_number()
            .to_bn()?
            .to_dec_str()?
            .to_string())
    }

    /// Use OpenSSL to cryptographically verify the NVIDIA certificate chain.
    ///
    /// Returns the signing certificate if its chain of trust can be verified all the
    /// way up to the trusted NVIDIA root CA.
    pub(super) fn verify(&self, expected_fwid: &str, architecture: Architecture) -> Result<()> {
        if self.certs.len() < 2 {
            bail!("Certificate chain must have at least the root CA and signing certificates");
        }

        self.check_root_ca_is_trusted()?;

        // Certificate used to verify the report signature
        let leaf_cert = self.get_leaf_certificate()?;

        // Check if leaf certificate FwId matches the FwId from the report
        let cert_fwid = get_fwid_from_cert(leaf_cert, architecture)?;
        if cert_fwid != expected_fwid {
            bail!(
                "Fwid mismatch: certificate {}, evidence {}",
                cert_fwid,
                expected_fwid
            );
        }

        // Trusted root certificate
        let trusted_certs = {
            let mut builder = X509StoreBuilder::new()?;
            builder.add_cert(NVIDIA_ROOT_CA.cert.clone())?;
            builder.build()
        };

        // Untrusted certificate chain
        // OpenSSL 1.1.0+ considers the root certificate to not be part of the chain
        let mut intermediate_certs = Stack::<X509>::new()?;
        let (_, certs_without_root) = self
            .certs
            .split_last()
            .ok_or(anyhow!("Failed to split NVIDIA certificates"))?;
        for cert in certs_without_root {
            intermediate_certs.push(cert.clone())?;
        }

        let mut context = X509StoreContext::new()?;
        let verified = context
            .init(&trusted_certs, leaf_cert, &intermediate_certs, |c| {
                c.verify_cert()
            })
            .map_err(|e| anyhow!(e.to_string()))?;

        if !verified {
            bail!("Report certificate chain failed to verify");
        }

        Ok(())
    }
}

fn get_fwid_from_cert(cert: &X509, architecture: Architecture) -> Result<String> {
    // TCG DICE Attestation Architecture v1.1 sections 6.1.1 and 6.1.1.3 define
    // DiceTcbInfo and its alias:
    // https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-Version-1.1-Revision-18_pub.pdf
    let fwid_oid = match architecture {
        Architecture::Hopper => oid!(2.23.133 .5 .4 .1),
        Architecture::Blackwell => oid!(2.23.133 .5 .4 .1 .1),
        Architecture::LS10 => bail!("LS10 certificate FWID extraction is not supported"),
    };

    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser
    let der: Vec<u8> = cert.to_der()?;
    let tbs_cert = X509Certificate::from_der(&der)?.1.tbs_certificate;

    let value = tbs_cert
        .get_extension_unique(&fwid_oid)?
        .ok_or_else(|| anyhow!("FwId oid not found in the NVIDIA signing certificate"))?
        .value;

    // NVIDIA's local verifier documents the architecture-specific extraction:
    // https://github.com/NVIDIA/nvtrust/blob/2026.06.04.001/guest_tools/gpu_verifiers/local_gpu_verifier/src/verifier/cc_admin_utils.py#L92-L109
    match architecture {
        Architecture::Hopper => {
            // Hopper uses NVIDIA's legacy encoding under the DiceTcbInfo OID.
            // NVIDIA's verifier extracts its SHA-384 FWID from the final 48 bytes.
            let fwid = value
                .get(value.len() - 48..)
                .ok_or(anyhow!("Unexpected fwid oid size"))?;
            Ok(hex::encode(fwid))
        }
        // nvtrust selects fwids[0] for Blackwell certificates; later entries
        // describe other firmware layers.
        Architecture::Blackwell => parse_dice_tcb_info_fwid(value),
        Architecture::LS10 => unreachable!("LS10 was rejected before extension parsing"),
    }
}

/// Parse `fwids[0]` from a TCG DICE `DiceTcbInfo` extension.
///
/// Blackwell certificates encode the FWID list as context-specific field `[6]`
/// using IMPLICIT tagging. Its payload is therefore the DER content of
/// `FWIDLIST`, a sequence of `FWID ::= SEQUENCE { hashAlg OID, digest OCTET STRING }`.
/// See section 6.1.1 of the TCG DICE Attestation Architecture v1.1:
/// <https://trustedcomputinggroup.org/wp-content/uploads/DICE-Attestation-Architecture-Version-1.1-Revision-18_pub.pdf>
fn parse_dice_tcb_info_fwid(value: &[u8]) -> Result<String> {
    let (remaining, tcb_info) = Sequence::from_der(value)
        .map_err(|e| anyhow!("Failed to parse DiceTcbInfo extension: {e}"))?;
    if !remaining.is_empty() {
        bail!("Unexpected trailing data in DiceTcbInfo extension");
    }

    let fields = tcb_info
        .der_iter::<Any<'_>, asn1_rs::Error>()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse DiceTcbInfo field: {e}"))?;
    let mut fwids = None;
    for field in fields {
        if field.class() == Class::ContextSpecific
            && field.tag() == Tag(6)
            && fwids.replace(field).is_some()
        {
            bail!("Duplicate DiceTcbInfo fwids field");
        }
    }
    let fwids = fwids.ok_or_else(|| anyhow!("DiceTcbInfo fwids field not found"))?;

    if !fwids.header.constructed() {
        bail!("DiceTcbInfo fwids field is not constructed");
    }

    let mut remainder = fwids.data;
    let mut first_digest = None;
    let mut index = 0;
    while !remainder.is_empty() {
        let (next, fwid) = Sequence::from_der(remainder)
            .map_err(|e| anyhow!("Failed to parse fwids[{index}]: {e}"))?;
        let digest = parse_fwid(fwid, index)?;
        first_digest = first_digest.or(digest);
        remainder = next;
        index += 1;
    }

    first_digest.ok_or_else(|| anyhow!("DiceTcbInfo fwids list is empty"))
}

fn parse_fwid(fwid: Sequence<'_>, index: usize) -> Result<Option<String>> {
    let fields = fwid
        .der_iter::<Any<'_>, asn1_rs::Error>()
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to parse fwids[{index}]: {e}"))?;
    if fields.len() != 2 {
        bail!("fwids[{index}] must contain exactly a hash algorithm and digest");
    }
    let hash_algorithm = &fields[0];
    let digest = &fields[1];

    if hash_algorithm.class() != Class::Universal || hash_algorithm.tag() != Tag::Oid {
        bail!("Invalid fwids[{index}] hash algorithm field");
    }
    let hash_algorithm = Oid::try_from(hash_algorithm)
        .map_err(|e| anyhow!("Invalid fwids[{index}] hash OID: {e}"))?;

    if digest.class() != Class::Universal || digest.tag() != Tag::OctetString {
        bail!("Invalid fwids[{index}] digest field");
    }
    let digest =
        OctetString::try_from(digest).map_err(|e| anyhow!("Invalid fwids[{index}] digest: {e}"))?;

    // NVIDIA defines fwids[0] as the report FWID. Other entries may use a
    // different algorithm and do not participate in this comparison.
    if index != 0 {
        return Ok(None);
    }
    if hash_algorithm != oid!(2.16.840 .1 .101 .3 .4 .2 .2) {
        bail!("fwids[0] does not use SHA-384");
    }
    if digest.as_ref().len() != 48 {
        bail!("fwids[0] SHA-384 digest must be 48 bytes");
    }

    Ok(Some(hex::encode(digest.as_ref())))
}

pub fn certificate_fingerprint(cert: &X509) -> Result<String> {
    let s = hex::encode(cert.digest(MessageDigest::sha1())?);
    Ok(s)
}

#[cfg(test)]
mod tests {
    use anyhow::{anyhow, Result};
    use openssl::x509::X509;
    use rstest::rstest;

    use crate::nvidia::{
        cert_chain::{get_fwid_from_cert, NvidiaCertificateChain},
        Architecture,
    };

    const EXPECTED_HOPPER_FWID: &str = "f5c384aebb579217a2c66b17ed0f28e6a9b8d639041acd7b4721cec004f7275494ba94bb5cdfdb3055ee051762b1f75d";
    const EXPECTED_BLACKWELL_FWID: &str = "9b92cc3e53b9265259e1abde163653288c2474fcafd8e5c0fd62ce9c9036fb62723fe3715b50f4ac27c68b62e2fd9240";
    const SHA384_OID: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 128 {
            encoded.push(content.len() as u8);
        } else {
            encoded.extend_from_slice(&[0x81, content.len() as u8]);
        }
        encoded.extend_from_slice(content);
        encoded
    }

    fn fwid(oid: &[u8], digest: &[u8]) -> Vec<u8> {
        let mut content = der(0x06, oid);
        content.extend(der(0x04, digest));
        der(0x30, &content)
    }

    fn dice_tcb_info(fwid_entries: &[Vec<u8>]) -> Vec<u8> {
        let fwids = fwid_entries.concat();
        der(0x30, &der(0xa6, &fwids))
    }

    #[rstest]
    // Case1: Valid Hopper certificate chain
    #[case(
        include_str!("../../test_data/nvidia/hopper_cert_chain_case1.txt"),
        Ok(())
    )]
    // Case2: Bad Hopper certificate chain. Only the root CA
    #[case(
        include_str!("../../test_data/nvidia/hopper_cert_chain_case2.txt"),
        Err(anyhow!("Certificate chain must have at least the root CA and signing certificates"))
    )]
    // Case3: Bad Hopper certificate chain. Missing intermediate CA
    #[case(
        include_str!("../../test_data/nvidia/hopper_cert_chain_case3.txt"),
        Err(anyhow!("Report certificate chain failed to verify"))
    )]
    // Case4: Bad Hopper certificate chain. Missing actual signing certificate
    #[case(
        include_str!("../../test_data/nvidia/hopper_cert_chain_case4.txt"),
        Err(anyhow!("FwId oid not found in the NVIDIA signing certificate"))
    )]
    fn test_verify_certificate_chain_for_hopper(
        #[case] cert_chain_str: &str,
        #[case] expected_result: Result<()>,
    ) {
        let cert_chain = NvidiaCertificateChain::decode(cert_chain_str.as_bytes()).unwrap();

        match cert_chain.verify(EXPECTED_HOPPER_FWID, Architecture::Hopper) {
            Ok(_) => assert!(expected_result.is_ok()),
            Err(e) => assert_eq!(e.to_string(), expected_result.unwrap_err().to_string()),
        }
    }

    #[rstest]
    // Case1: Valid Blackwell certificate chain captured from RTX PRO 6000 hardware
    #[case(
        include_str!("../../test_data/nvidia/blackwell_cert_chain_case1.txt"),
        Ok(())
    )]
    // Case2: Bad Blackwell certificate chain. Only the root CA
    #[case(
        include_str!("../../test_data/nvidia/blackwell_cert_chain_case2.txt"),
        Err(anyhow!("Certificate chain must have at least the root CA and signing certificates"))
    )]
    // Case3: Bad Blackwell certificate chain. Missing Provisioner ICA
    #[case(
        include_str!("../../test_data/nvidia/blackwell_cert_chain_case3.txt"),
        Err(anyhow!("Report certificate chain failed to verify"))
    )]
    fn test_verify_certificate_chain_for_blackwell(
        #[case] cert_chain_str: &str,
        #[case] expected_result: Result<()>,
    ) {
        let cert_chain = NvidiaCertificateChain::decode(cert_chain_str.as_bytes()).unwrap();

        match cert_chain.verify(EXPECTED_BLACKWELL_FWID, Architecture::Blackwell) {
            Ok(_) => assert!(expected_result.is_ok()),
            Err(e) => assert_eq!(e.to_string(), expected_result.unwrap_err().to_string()),
        }
    }

    #[test]
    fn test_blackwell_certificate_fwid_must_match_report() {
        let cert_chain = NvidiaCertificateChain::decode(include_bytes!(
            "../../test_data/nvidia/blackwell_cert_chain_case1.txt"
        ))
        .unwrap();
        let evidence_fwid = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        let error = cert_chain
            .verify(evidence_fwid, Architecture::Blackwell)
            .unwrap_err();

        assert_eq!(
            error.to_string(),
            format!(
                "Fwid mismatch: certificate {EXPECTED_BLACKWELL_FWID}, evidence {evidence_fwid}"
            )
        );
    }

    #[rstest]
    #[case::hopper(
        "../../test_data/nvidia/hopper_signing_cert.pem",
        include_bytes!("../../test_data/nvidia/hopper_signing_cert.pem"),
        Architecture::Hopper,
        EXPECTED_HOPPER_FWID
    )]
    #[case::blackwell(
        "../../test_data/nvidia/blackwell_signing_cert.pem",
        include_bytes!("../../test_data/nvidia/blackwell_signing_cert.pem"),
        Architecture::Blackwell,
        EXPECTED_BLACKWELL_FWID
    )]
    fn test_parse_fwid_from_certificate(
        #[case] cert_name: &str,
        #[case] cert_bytes: &[u8],
        #[case] architecture: Architecture,
        #[case] expected_fwid: &str,
    ) {
        let signing_cert = X509::from_pem(cert_bytes)
            .map_err(|_| anyhow!("{cert_name} failed to read"))
            .unwrap();
        let fwid = get_fwid_from_cert(&signing_cert, architecture).unwrap();
        assert_eq!(expected_fwid, fwid);
    }

    #[rstest]
    #[case::hopper(
        include_bytes!("../../test_data/nvidia/hopper_cert_chain_case1.txt"),
        "478176379286082186618948445787393647364802107249"
    )]
    #[case::blackwell(
        include_bytes!("../../test_data/nvidia/blackwell_cert_chain_case1.txt"),
        "408762037488965241743361667085904172082023387885"
    )]
    fn test_ueid_is_leaf_certificate_serial(
        #[case] certificate_chain: &[u8],
        #[case] expected: &str,
    ) {
        let certificate_chain = NvidiaCertificateChain::decode(certificate_chain).unwrap();

        assert_eq!(certificate_chain.ueid().unwrap(), expected);
    }

    #[test]
    fn test_dice_tcb_info_returns_first_fwid() {
        let first = [0x11; 48];
        let sha256_oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
        let second = [0x22; 32];
        let value = dice_tcb_info(&[fwid(SHA384_OID, &first), fwid(&sha256_oid, &second)]);

        assert_eq!(
            super::parse_dice_tcb_info_fwid(&value).unwrap(),
            hex::encode(first)
        );
    }

    #[test]
    fn test_dice_tcb_info_rejects_malformed_structures() {
        let digest = [0x11; 48];
        let valid_fwid = fwid(SHA384_OID, &digest);
        let valid_field = der(0xa6, &valid_fwid);

        let mut duplicate_fields = valid_field.clone();
        duplicate_fields.extend(valid_field.clone());

        let mut malformed_trailing_fwid = valid_fwid.clone();
        malformed_trailing_fwid.extend([0x30, 0x00]);

        let mut trailing_outer_data = dice_tcb_info(std::slice::from_ref(&valid_fwid));
        trailing_outer_data.push(0);

        let mut wrong_oid = SHA384_OID.to_vec();
        *wrong_oid.last_mut().unwrap() = 1;

        let cases = [
            ("missing fwids", der(0x30, &[])),
            ("duplicate fwids", der(0x30, &duplicate_fields)),
            ("primitive fwids", der(0x30, &der(0x86, &valid_fwid))),
            ("empty fwids", der(0x30, &der(0xa6, &[]))),
            (
                "wrong hash algorithm",
                dice_tcb_info(&[fwid(&wrong_oid, &digest)]),
            ),
            (
                "wrong digest length",
                dice_tcb_info(&[fwid(SHA384_OID, &[0x11; 47])]),
            ),
            (
                "malformed trailing fwid",
                der(0x30, &der(0xa6, &malformed_trailing_fwid)),
            ),
            ("outer trailing data", trailing_outer_data),
        ];

        for (name, value) in cases {
            assert!(
                super::parse_dice_tcb_info_fwid(&value).is_err(),
                "{name} unexpectedly parsed"
            );
        }
    }
}
