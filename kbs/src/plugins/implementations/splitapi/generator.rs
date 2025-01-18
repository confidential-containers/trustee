// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::X509Builder;
use openssl::x509::{X509Name, X509NameBuilder, X509Req, X509ReqBuilder, X509};
use serde::Deserialize;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
use tempfile::TempDir;

use super::manager::Credentials;

pub const CA_KEY_FILENAME: &str = "ca.key";
pub const CA_CRT_FILENAME: &str = "ca.pem";
pub const CLIENT_KEY_FILENAME: &str = "client.key";
pub const CLIENT_CSR_FILENAME: &str = "client.csr";
pub const CLIENT_CRT_FILENAME: &str = "client.pem";
pub const SERVER_KEY_FILENAME: &str = "server.key";
pub const SERVER_CSR_FILENAME: &str = "server.csr";
pub const SERVER_CRT_FILENAME: &str = "server.pem";

const KEY_SIZE: u32 = 2048;

/// Default certificate details if not configured
pub const DEFAULT_COUNTRY: &str = "AA";
pub const DEFAULT_STATE: &str = "Default State";
pub const DEFAULT_LOCALITY: &str = "Default City";
pub const DEFAULT_ORGANIZATION: &str = "Default Organization";
pub const DEFAULT_ORG_UNIT: &str = "Default Unit";
pub const DEFAULT_CA_COMMON_NAME: &str = "grpc-tls CA";
pub const DEFAULT_SERVER_COMMON_NAME: &str = "server";
pub const DEFAULT_CLIENT_COMMON_NAME: &str = "client";
pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 3650;
pub const DEFAULT_SERVER_VALIDITY_DAYS: u32 = 180;
pub const DEFAULT_CLIENT_VALIDITY_DAYS: u32 = 180;

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct CertificateDetails {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub org_unit: String,
    pub ca: Certificate,
    pub server: Certificate,
    pub client: Certificate,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Certificate {
    pub common_name: String,
    pub validity_days: u32,
}

impl Default for CertificateDetails {
    fn default() -> Self {
        CertificateDetails {
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            locality: DEFAULT_LOCALITY.to_string(),
            organization: DEFAULT_ORGANIZATION.to_string(),
            org_unit: DEFAULT_ORG_UNIT.to_string(),
            ca: Certificate {
                common_name: DEFAULT_CA_COMMON_NAME.to_string(),
                validity_days: DEFAULT_CA_VALIDITY_DAYS,
            },
            server: Certificate {
                common_name: DEFAULT_SERVER_COMMON_NAME.to_string(),
                validity_days: DEFAULT_SERVER_VALIDITY_DAYS,
            },
            client: Certificate {
                common_name: DEFAULT_CLIENT_COMMON_NAME.to_string(),
                validity_days: DEFAULT_CLIENT_VALIDITY_DAYS,
            },
        }
    }
}

#[derive(Debug)]
pub struct CredentialGenerator {
    key_size: u32,
    ca_key: PathBuf,
    ca_crt: PathBuf,
    client_key: PathBuf,
    client_csr: PathBuf,
    client_crt: PathBuf,
    server_key: PathBuf,
    server_csr: PathBuf,
    server_crt: PathBuf,
}

impl CredentialGenerator {
    pub fn new(cred_dir: &TempDir) -> Result<Self> {
        Ok(Self {
            key_size: KEY_SIZE,
            ca_key: cred_dir.path().to_owned().join(CA_KEY_FILENAME),
            ca_crt: cred_dir.path().to_owned().join(CA_CRT_FILENAME),
            client_key: cred_dir.path().to_owned().join(CLIENT_KEY_FILENAME),
            client_csr: cred_dir.path().to_owned().join(CLIENT_CSR_FILENAME),
            client_crt: cred_dir.path().to_owned().join(CLIENT_CRT_FILENAME),
            server_key: cred_dir.path().to_owned().join(SERVER_KEY_FILENAME),
            server_csr: cred_dir.path().to_owned().join(SERVER_CSR_FILENAME),
            server_crt: cred_dir.path().to_owned().join(SERVER_CRT_FILENAME),
        })
    }

    /// Run several steps for generate all the keys and certificates
    pub fn generate(&self, cert_details: &CertificateDetails) -> Result<Credentials> {
        // Create CA key, and self-signed certificate (valid for 10 years)
        self.generate_private_key(self.ca_key.as_path(), self.key_size)?;
        let ca_x509_name = self.build_x509_name(
            &cert_details.ca.common_name,
            &cert_details.country,
            &cert_details.state,
            &cert_details.locality,
            &cert_details.organization,
            &cert_details.org_unit,
        )?;
        self.generate_ca_cert(
            self.ca_crt.as_path(),
            self.ca_key.as_path(),
            &ca_x509_name,
            cert_details.ca.validity_days,
        )?;

        // Create server key, csr, and certificate
        self.generate_private_key(self.server_key.as_path(), self.key_size)?;
        let server_x509_name = self.build_x509_name(
            &cert_details.server.common_name,
            &cert_details.country,
            &cert_details.state,
            &cert_details.locality,
            &cert_details.organization,
            &cert_details.org_unit,
        )?;
        self.generate_csr(
            self.server_csr.as_path(),
            self.server_key.as_path(),
            &server_x509_name,
        )?;
        self.generate_cert(
            self.server_crt.as_path(),
            self.server_csr.as_path(),
            self.ca_crt.as_path(),
            self.ca_key.as_path(),
            cert_details.server.validity_days,
        )?;

        // Create client key, csr, and certificate
        self.generate_private_key(self.client_key.as_path(), self.key_size)?;
        let client_x509_name = self.build_x509_name(
            &cert_details.client.common_name,
            &cert_details.country,
            &cert_details.state,
            &cert_details.locality,
            &cert_details.organization,
            &cert_details.org_unit,
        )?;
        self.generate_csr(
            self.client_csr.as_path(),
            self.client_key.as_path(),
            &client_x509_name,
        )?;
        self.generate_cert(
            self.client_crt.as_path(),
            self.client_csr.as_path(),
            self.ca_crt.as_path(),
            self.ca_key.as_path(),
            cert_details.client.validity_days,
        )?;

        // Read the generated credentials
        let read_cred =
            |path: &Path| fs::read(path).with_context(|| format!("read {}", path.display()));

        let credentials = Credentials {
            ca_crt: read_cred(self.ca_crt.as_path())?,
            client_key: read_cred(self.client_key.as_path())?,
            client_crt: read_cred(self.client_crt.as_path())?,
            server_key: read_cred(self.server_key.as_path())?,
            server_crt: read_cred(self.server_crt.as_path())?,
        };

        Ok(credentials)
    }

    fn generate_private_key(&self, ca_key_path: &Path, key_size: u32) -> Result<()> {
        // Generate RSA key
        let rsa = Rsa::generate(key_size).expect("Failed to generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA");

        // Write the private key to a file
        let private_key_pem = pkey.private_key_to_pem_pkcs8()?;
        let mut file = File::create(ca_key_path)?;
        file.write_all(&private_key_pem)?;

        Ok(())
    }

    fn build_x509_name(
        &self,
        common_name: &str,
        country: &str,
        state: &str,
        locality: &str,
        organization: &str,
        org_unit: &str,
    ) -> Result<X509Name> {
        // Build X.509 name
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", country)?;
        name_builder.append_entry_by_text("ST", state)?;
        name_builder.append_entry_by_text("L", locality)?;
        name_builder.append_entry_by_text("O", organization)?;
        name_builder.append_entry_by_text("OU", org_unit)?;
        name_builder.append_entry_by_text("CN", common_name)?;
        let name = name_builder.build();

        Ok(name)
    }

    fn generate_ca_cert(
        &self,
        crt_path: &Path,
        ca_key_path: &Path,
        name: &X509Name,
        validity_days: u32,
    ) -> Result<()> {
        // Read the private key from file
        let mut file = File::open(ca_key_path)?;
        let mut key_pem = Vec::new();
        file.read_to_end(&mut key_pem)?;
        let rsa = Rsa::private_key_from_pem(&key_pem)?;
        let pkey = PKey::from_rsa(rsa)?;

        // Build the X.509 certificate
        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(name)?;
        x509_builder.set_issuer_name(name)?;
        x509_builder.set_pubkey(&pkey)?;

        // Set certificate validity period
        x509_builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("Failed to set not before"))
            .expect("Failed to set not before");
        x509_builder
            .set_not_after(
                &Asn1Time::days_from_now(validity_days).expect("Failed to set not after"),
            )
            .expect("Failed to set not after");

        // Sign the certificate
        x509_builder.sign(&pkey, MessageDigest::sha256())?;
        let x509 = x509_builder.build();

        // Write the certificate to a file
        let crt_pem = x509.to_pem()?;
        let mut crt_file = File::create(crt_path)?;
        crt_file.write_all(&crt_pem)?;

        Ok(())
    }

    fn generate_csr(
        &self,
        csr_path: &Path,
        private_key_path: &Path,
        name: &X509Name,
    ) -> Result<()> {
        // Read the private key from file
        let mut file = File::open(private_key_path)?;
        let mut key_pem = Vec::new();
        file.read_to_end(&mut key_pem)?;
        let rsa = Rsa::private_key_from_pem(&key_pem)?;
        let pkey = PKey::from_rsa(rsa)?;

        // Create a new X.509 certificate signing request (CSR)
        let mut csr_builder = X509ReqBuilder::new()?;
        csr_builder.set_subject_name(name)?;
        csr_builder.set_pubkey(&pkey)?;
        csr_builder.sign(&pkey, MessageDigest::sha256())?;

        let csr = csr_builder.build();

        // Write CSR to a file
        let mut csr_file = File::create(csr_path)?;
        csr_file.write_all(&csr.to_pem()?)?;

        Ok(())
    }

    fn generate_cert(
        &self,
        crt_path: &Path,
        csr_path: &Path,
        ca_crt_path: &Path,
        ca_key_path: &Path,
        validity_days: u32,
    ) -> Result<()> {
        // Step 1: Read the CSR
        let mut csr_file = File::open(csr_path)?;
        let mut csr_data = vec![];
        csr_file.read_to_end(&mut csr_data)?;
        let csr = X509Req::from_pem(&csr_data)?;

        // Step 2: Read the CA PEM
        let mut ca_file = File::open(ca_crt_path)?;
        let mut ca_data = vec![];
        ca_file.read_to_end(&mut ca_data)?;
        let ca_cert = X509::from_pem(&ca_data)?;

        // Step 3: Read the CA Key
        let mut ca_key_file = File::open(ca_key_path)?;
        let mut ca_key_data = vec![];
        ca_key_file.read_to_end(&mut ca_key_data)?;
        let ca_key = PKey::private_key_from_pem(&ca_key_data)?;

        // Step 5: Create the server certificate
        let mut builder = X509Builder::new()?;

        // Set the version of the certificate
        builder.set_version(2)?;

        // Set the serial number
        let serial_number = {
            let mut serial = BigNum::new()?;
            serial.rand(159, openssl::bn::MsbOption::MAYBE_ZERO, false)?;
            serial.to_asn1_integer()?
        };
        builder.set_serial_number(&serial_number)?;

        // Set the subject name from the CSR
        builder.set_subject_name(csr.subject_name())?;
        //TODO: add sandbox IP in the subject

        // Set the issuer name from the CA certificate
        builder.set_issuer_name(ca_cert.subject_name())?;

        // Set the public key from the CSR
        let public_key = csr.public_key()?;
        builder.set_pubkey(&public_key)?;

        // Set the certificate validity period
        let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
        let not_after = openssl::asn1::Asn1Time::days_from_now(validity_days)?;
        builder.set_not_before(&not_before)?;
        builder.set_not_after(&not_after)?;

        // Add extensions from the certificate extensions file
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        builder.append_extension(
            SubjectKeyIdentifier::new().build(&builder.x509v3_context(None, None))?,
        )?;
        builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&builder.x509v3_context(Some(&ca_cert), None))?,
        )?;

        // Sign the certificate with the CA key
        builder.sign(&ca_key, MessageDigest::sha256())?;

        // Write the server certificate to a file
        let server_crt = builder.build().to_pem()?;
        let mut crt_file = File::create(crt_path)?;
        crt_file.write_all(&server_crt)?;

        Ok(())
    }
}
