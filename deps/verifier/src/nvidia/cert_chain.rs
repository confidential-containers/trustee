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
use x509_parser::{prelude::X509Certificate};

pub struct NvidiaCertificate {
    cert: X509,
    digest: String,
}

static NVIDIA_ROOT_CA: LazyLock<NvidiaCertificate> = 
    LazyLock::new(|| {
        let cert = X509::from_pem(include_bytes!("nvidia_device_root.pem")).unwrap();
        let digest = certificate_fingerprint(&cert).unwrap();
        NvidiaCertificate { cert, digest }
    }
);

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
        self.certs
            .last()
            .ok_or(anyhow!("Root CA certificate not found in the NVIDIA certificate chain"))
    }

    pub fn get_leaf_certificate(&self) -> Result<&X509> {
        self.certs
            .get(0)
            .ok_or(anyhow!("Leaf certificate not found in the NVIDIA certificate chain"))
    }

    /// Use OpenSSL to cryptographically verify the NVIDIA certificate chain.
    /// 
    /// Returns the signing certificate if its chain of trust can be verified all the
    /// way up to the trusted NVIDIA root CA.
    pub fn verify(&self, expected_fwid: &str) -> Result<&X509> {
        if self.certs.len() < 2 {
            bail!("Certificate chain must be >= 2");
        }

        self.check_root_ca_is_trusted()?;

        // Signing certificate to be verified its chain of trust
        let leaf_cert = self.get_leaf_certificate()?;

        // Check if leaf certificate FwId matches the expected one
        let cert_fwid = get_fwid_from_cert(leaf_cert)?;
        if cert_fwid != expected_fwid {
            bail!("Fwid mismatch: certificate {}, evidence {}", cert_fwid, expected_fwid);
        }

        // Trusted root certificate
        let trusted_certs = {
            let mut builder = X509StoreBuilder::new().unwrap();
            builder.add_cert(NVIDIA_ROOT_CA.cert.clone())?;
            builder.build()
        };

        // Untrusted certificate chain
        // OpenSSL 1.1.0+ considers the root certificate to not be part of the chain, while 1.0.2 and LibreSSL do
        let mut intermediate_certs = Stack::<X509>::new().unwrap();
        for index in 1..self.certs.len()-1 {
            intermediate_certs.push(self.certs[index].clone())?;
        }

        let mut context = X509StoreContext::new().unwrap();
        let verified = context
            .init(
                &trusted_certs,
                leaf_cert,
                &intermediate_certs,
                |c| c.verify_cert()
            )
            .map_err(|e| anyhow!(e.to_string()))?;

        if !verified {
            bail!("Leaf certificate failed to verify the certificate");
        }
        
        Ok(leaf_cert)
    }
}

pub fn get_fwid_from_cert(cert: &X509) -> Result<String>{
    let fwid_oid = oid!(2.23.133.5.4.1);

    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser
    let der: Vec<u8> = cert.to_der()?;
    let tbs_cert = X509Certificate::from_der(&der)?
        .1
        .tbs_certificate;

    let value = tbs_cert
        .get_extension_unique(&fwid_oid)?
        .ok_or_else(|| anyhow!("FwId oid not found in the NVIDIA signing certificate"))?
        .value;

    // The FwId data is the last 48 bytes
    let fwid = value
        .windows(48)
        .rev()
        .next()
        .ok_or(anyhow!("Unexpected oid data size "))?;

    Ok(hex::encode(fwid))
}

pub fn certificate_fingerprint(cert: &X509) -> Result<String> {
    let s = hex::encode(cert.digest(MessageDigest::sha1())?);
    Ok(s)
}