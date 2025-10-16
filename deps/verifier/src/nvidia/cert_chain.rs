// Copyright (c) 2025 IBM Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use asn1_rs::{oid, FromDer};
use openssl::hash::MessageDigest;
use openssl::stack::Stack;
use openssl::x509::{store::X509StoreBuilder, X509StoreContext, X509};
use std::sync::LazyLock;
use x509_parser::prelude::X509Certificate;

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

    /// Use OpenSSL to cryptographically verify the NVIDIA certificate chain.
    ///
    /// Returns the signing certificate if its chain of trust can be verified all the
    /// way up to the trusted NVIDIA root CA.
    pub fn verify(&self, expected_fwid: &str) -> Result<()> {
        if self.certs.len() < 2 {
            bail!("Certificate chain must have at least the root CA and signing certificates");
        }

        self.check_root_ca_is_trusted()?;

        // Certificate used to verify the report signature
        let leaf_cert = self.get_leaf_certificate()?;

        // Check if leaf certificate FwId matches the FwId from the report
        let cert_fwid = get_fwid_from_cert(leaf_cert)?;
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

pub fn get_fwid_from_cert(cert: &X509) -> Result<String> {
    let fwid_oid = oid!(2.23.133 .5 .4 .1);

    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser
    let der: Vec<u8> = cert.to_der()?;
    let tbs_cert = X509Certificate::from_der(&der)?.1.tbs_certificate;

    let value = tbs_cert
        .get_extension_unique(&fwid_oid)?
        .ok_or_else(|| anyhow!("FwId oid not found in the NVIDIA signing certificate"))?
        .value;

    // The FwId data is the last 48 bytes
    let fwid = value
        .get(value.len() - 48..)
        .ok_or(anyhow!("Unexpected fwid oid size"))?;

    Ok(hex::encode(fwid))
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

    use crate::nvidia::cert_chain::{get_fwid_from_cert, NvidiaCertificateChain};

    const EXPECTED_FWID: &str = "f5c384aebb579217a2c66b17ed0f28e6a9b8d639041acd7b4721cec004f7275494ba94bb5cdfdb3055ee051762b1f75d";

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

        match cert_chain.verify(EXPECTED_FWID) {
            Ok(_) => assert!(expected_result.is_ok()),
            Err(e) => assert_eq!(e.to_string(), expected_result.unwrap_err().to_string()),
        }
    }

    #[test]
    // The FwId is last 48 bytes of the "2.23.133.5.4.1" extension
    // Command: openssl asn1parse -i -in hopper_singing_cert.pem
    fn test_parse_fwid_from_certificate() {
        let signing_cert = X509::from_pem(include_bytes!(
            "../../test_data/nvidia/hopper_signing_cert.pem"
        ))
        .map_err(|_| anyhow!("hopper_singing_cert.pem failed to read"))
        .unwrap();
        let fwid = get_fwid_from_cert(&signing_cert).unwrap();
        assert_eq!(EXPECTED_FWID.to_string(), fwid);
    }
}
