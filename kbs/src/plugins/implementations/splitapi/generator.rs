// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use openssl::rsa::Rsa;
use openssl::x509::{X509NameBuilder, X509Name, X509, X509ReqBuilder, X509Req};
use openssl::x509::extension::BasicConstraints;
use openssl::x509::extension::KeyUsage;
use openssl::x509::extension::SubjectKeyIdentifier;
use openssl::x509::extension::AuthorityKeyIdentifier;
use openssl::pkey::PKey;
use openssl::x509::X509Builder;
use openssl::hash::MessageDigest;
use std::fs::File;
use std::io::Write;
use std::io::Read;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use std::path::PathBuf;
use std::error::Error;
use anyhow::Result;

use super::backend::SandboxParams;


pub const CA_KEY_FILENAME: &str = "ca.key";
pub const CA_CRT_FILENAME: &str = "ca.pem";
pub const CLIENT_KEY_FILENAME: &str = "client.key";
pub const CLIENT_CSR_FILENAME: &str = "client.csr";
pub const CLIENT_CRT_FILENAME: &str = "client.pem";
pub const SERVER_KEY_FILENAME: &str = "server.key";
pub const SERVER_CSR_FILENAME: &str = "server.csr";
pub const SERVER_CRT_FILENAME: &str = "server.pem";

const CREDENTIAL_KEY_SIZE: u32 = 2048;


#[derive(Debug, serde::Serialize)]
pub struct ServerCredential {
    pub key: Vec<u8>,
    pub crt: Vec<u8>,
    pub ca_crt: Vec<u8>,
}


/// Credentials (keys and certs for ca, server, and client) stored 
/// in plugin_dir/sandbox-specific-directory
#[derive(Debug)]
pub struct CredentialBundle {
    key_size: u32,
    ca_key: PathBuf,
    ca_crt: PathBuf,
    client_key: PathBuf,
    client_csr: PathBuf,
    client_crt: PathBuf,
    server_key: PathBuf,
    server_csr: PathBuf,
    server_crt: PathBuf
}

impl CredentialBundle {
    pub fn new(sandbox_dir: &PathBuf) -> Result<Self> {
        let ca_key: PathBuf = sandbox_dir.as_path().join(CA_KEY_FILENAME);
        let ca_crt: PathBuf = sandbox_dir.as_path().join(CA_CRT_FILENAME);

        let client_key: PathBuf = sandbox_dir.as_path().join(CLIENT_KEY_FILENAME);
        let client_csr: PathBuf = sandbox_dir.as_path().join(CLIENT_CSR_FILENAME);
        let client_crt: PathBuf = sandbox_dir.as_path().join(CLIENT_CRT_FILENAME);

        let server_key: PathBuf = sandbox_dir.as_path().join(SERVER_KEY_FILENAME);
        let server_csr: PathBuf = sandbox_dir.as_path().join(SERVER_CSR_FILENAME);
        let server_crt: PathBuf = sandbox_dir.as_path().join(SERVER_CRT_FILENAME);

        Ok(Self {
            key_size: CREDENTIAL_KEY_SIZE,
            ca_key,
            ca_crt,
            client_key,
            client_csr,
            client_crt,
            server_key,
            server_csr,
            server_crt
        })
    }
    pub fn server_key(&self) -> &PathBuf {
        &self.server_key
    }

    pub fn server_crt(&self) -> &PathBuf {
        &self.server_crt
    }

    pub fn ca_crt(&self) -> &PathBuf {
        &self.ca_crt
    }

    /// Run several steps for generate all the keys and certificates
    pub fn generate(
        &self,
        params: &SandboxParams,
    ) -> Result<&Self> {
        //let mut args: Vec<OsString> = Vec::from(params);
        log::info!("Params {:?}", params);

        match self.generate_private_key(&self.ca_key, self.key_size) {
            Ok(_) => println!("CA key generation succeeded and saved to {}.", self.ca_key.display()),
            Err(e) => eprintln!("CA key generation failed: {}", e),
        }

        match self.generate_ca_cert(&self.ca_crt, &self.ca_key) {
            Ok(_) => println!("CA self-signed certificate generated and saved to {}.", self.ca_crt.display()),
            Err(e) => eprintln!("CA self-signed certificate generation failed: {}", e),
        }

        match self.generate_private_key(&self.server_key, self.key_size) {
            Ok(_) => println!("Server key generation succeeded and saved to {}.", self.server_key.display()),
            Err(e) => eprintln!("Server key generation failed: {}", e),
        }

        let server_common_name = "server";
        match self.generate_csr(&self.server_csr, &self.server_key, server_common_name) {
            Ok(_) => println!("Server csr generation succeeded and saved to {}.", self.server_csr.display()),
            Err(e) => eprintln!("Server csr generation failed: {}", e),
        }

        match self.generate_cert(&self.server_crt, &self.server_csr, &self.ca_crt, &self.ca_key) {
            Ok(_) => println!("Server cert generation succeeded and saved to {}.", self.server_crt.display()),
            Err(e) => eprintln!("Server cert generation failed: {}", e),
        }

        match self.generate_private_key(&self.client_key, self.key_size) {
            Ok(_) => println!("Client key generation succeeded and saved to {}.", self.client_key.display()),
            Err(e) => eprintln!("Client key generation failed: {}", e),
        }

        let client_common_name = "client";
        match self.generate_csr(&self.client_csr, &self.client_key, client_common_name) {
            Ok(_) => println!("Client CSR generation succeeded and saved to {}.", self.client_csr.display()),
            Err(e) => eprintln!("Client CSR generation failed: {}", e),
        }

        match self.generate_cert(&self.client_crt, &self.client_csr, &self.ca_crt, &self.ca_key) {
            Ok(_) => println!("Client cert generation succeeded and saved to {}.", self.client_crt.display()),
            Err(e) => eprintln!("Client cert generation failed: {}", e),
        }

        Ok(self)
    }

    fn generate_private_key(
        &self, 
        ca_key_path: &PathBuf, 
        key_size: u32
    ) -> Result<(), Box<dyn Error>> {
        // Generate RSA key
        let rsa = Rsa::generate(key_size).expect("Failed to generate RSA key");
        let pkey = PKey::from_rsa(rsa).expect("Failed to create PKey from RSA");
    
        // Write the private key to a file
        let private_key_pem = pkey.private_key_to_pem_pkcs8()?;
        let mut file = File::create(ca_key_path.as_path())?;
        file.write_all(&private_key_pem)?;
    
        Ok(())
    }

    fn build_x509_name(
        &self, 
        common_name: &str
    ) -> Result<X509Name, Box<dyn std::error::Error>> {
        // Define certificate details
        let country = "AA";
        let state = "Default State";
        let locality = "Default City";
        let organization = "Default Organization";
        let org_unit = "Default Unit";
    
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
        crt_path: &PathBuf, 
        ca_key_path: &PathBuf
    ) -> Result<(), Box<dyn Error>> {
        // Read the private key from file
        let mut file = File::open(ca_key_path.as_path())?;
        let mut key_pem = Vec::new();
        file.read_to_end(&mut key_pem)?;
        let rsa = Rsa::private_key_from_pem(&key_pem)?;
        let pkey = PKey::from_rsa(rsa)?;
    
        // Build X.509 name
        let common_name = "grpc-tls CA";
        let name = self.build_x509_name(common_name)?;
    
        // Build the X.509 certificate
        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(&name)?;
        x509_builder.set_pubkey(&pkey)?;
    
        // Set certificate validity period
        x509_builder.set_not_before(
                &Asn1Time::days_from_now(0).expect("Failed to set not before")
            ).expect("Failed to set not before");
        x509_builder.set_not_after(
                &Asn1Time::days_from_now(3650).expect("Failed to set not after")
            ).expect("Failed to set not after");
     
        // Sign the certificate
        x509_builder.sign(&pkey, MessageDigest::sha256())?;
        let x509 = x509_builder.build();
    
        // Write the certificate to a file
        let crt_pem = x509.to_pem()?;
        let mut crt_file = File::create(crt_path.as_path())?;
        crt_file.write_all(&crt_pem)?;
    
        Ok(())
    }
    
    fn generate_csr(
        &self, 
        csr_path: &PathBuf, 
        private_key_path: &PathBuf, 
        common_name: &str
    ) -> Result<(), Box<dyn Error>> {
        
        // Read the private key from file
        let mut file = File::open(private_key_path.as_path())?;
        let mut key_pem = Vec::new();
        file.read_to_end(&mut key_pem)?;
        let rsa = Rsa::private_key_from_pem(&key_pem)?;
        let pkey = PKey::from_rsa(rsa)?;
    
        // Build X.509 name
        let name = self.build_x509_name(common_name)?;
       
        // Create a new X.509 certificate signing request (CSR)
        let mut csr_builder = X509ReqBuilder::new()?;
        csr_builder.set_subject_name(&name)?;
        csr_builder.set_pubkey(&pkey)?;
        csr_builder.sign(&pkey, MessageDigest::sha256())?;
       
        let csr = csr_builder.build();
    
        // Write CSR to a file
        let mut csr_file = File::create(csr_path.as_path())?;
        csr_file.write_all(&csr.to_pem()?)?;
    
        Ok(())
    }
    
    fn generate_cert(
        &self, 
        crt_path: &PathBuf, 
        csr_path: &PathBuf, 
        ca_crt_path: &PathBuf, 
        ca_key_path: &PathBuf
    ) -> Result<(), Box<dyn Error>> {
        // Step 1: Read the CSR
        let mut csr_file = File::open(csr_path.as_path())?;
        let mut csr_data = vec![];
        csr_file.read_to_end(&mut csr_data)?;
        let csr = X509Req::from_pem(&csr_data)?;
    
        // Step 2: Read the CA PEM
        let mut ca_file = File::open(ca_crt_path.as_path())?;
        let mut ca_data = vec![];
        ca_file.read_to_end(&mut ca_data)?;
        let ca_cert = X509::from_pem(&ca_data)?;
    
        // Step 3: Read the CA Key
        let mut ca_key_file = File::open(ca_key_path.as_path())?;
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
        let not_after = openssl::asn1::Asn1Time::days_from_now(3650)?; 
        builder.set_not_before(&not_before)?; 
        builder.set_not_after(&not_after)?;
    
        // Add extensions from the certificate extensions file 
        builder.append_extension(BasicConstraints::new().critical().build()?)?; 
        builder.append_extension(
            KeyUsage::new()
            .digital_signature()
            .key_encipherment().build()?
        )?; 
        builder.append_extension(
            SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))?
        )?; 
        builder.append_extension(
            AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&builder.x509v3_context(Some(&ca_cert), None))?
        )?;
    
        // Sign the certificate with the CA key 
        builder.sign(&ca_key, MessageDigest::sha256())?; 
        
        // Write the server certificate to a file 
        let server_crt = builder.build().to_pem()?; 
        let mut crt_file = File::create(crt_path.as_path())?;
        crt_file.write_all(&server_crt)?;
    
        Ok(())
    }
}