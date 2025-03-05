// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{
    extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    X509Builder, X509Name, X509NameBuilder, X509,
};
use serde::{Deserialize, Serialize};

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
pub struct PKIVaultCertDetails {
    /// Two-letter country code represents the country in which the entity resides
    pub country: String,
    /// State or province where the entity is located
    pub state: String,
    /// Locality or city where the entity is located
    pub locality: String,
    /// Organization or company name
    pub organization: String,
    /// An organizational unit within the organization
    pub org_unit: String,
    /// Information regarding the CA certificate
    pub ca: CaCrtDetails,
    /// Information regarding the server certificate
    pub server: ServerCrtDetails,
    /// Information regarding the client certificate
    pub client: ClientCrtDetails,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct CaCrtDetails {
    pub common_name: String,
    pub validity_days: u32,
}

impl Default for CaCrtDetails {
    fn default() -> Self {
        CaCrtDetails {
            common_name: DEFAULT_CA_COMMON_NAME.to_string(),
            validity_days: DEFAULT_CA_VALIDITY_DAYS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct ServerCrtDetails {
    pub common_name: String,
    pub validity_days: u32,
}

impl Default for ServerCrtDetails {
    fn default() -> Self {
        ServerCrtDetails {
            common_name: DEFAULT_SERVER_COMMON_NAME.to_string(),
            validity_days: DEFAULT_SERVER_VALIDITY_DAYS,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct ClientCrtDetails {
    pub common_name: String,
    pub validity_days: u32,
}

impl Default for ClientCrtDetails {
    fn default() -> Self {
        ClientCrtDetails {
            common_name: DEFAULT_CLIENT_COMMON_NAME.to_string(),
            validity_days: DEFAULT_CLIENT_VALIDITY_DAYS,
        }
    }
}

impl Default for PKIVaultCertDetails {
    fn default() -> Self {
        PKIVaultCertDetails {
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            locality: DEFAULT_LOCALITY.to_string(),
            organization: DEFAULT_ORGANIZATION.to_string(),
            org_unit: DEFAULT_ORG_UNIT.to_string(),
            ca: CaCrtDetails::default(),
            server: ServerCrtDetails::default(),
            client: ClientCrtDetails::default(),
        }
    }
}

/// Credential necessary for mutual TLS communication
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credential {
    pub ca_cert: Vec<u8>,
    pub server_key: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub client_cert: Vec<u8>,
}

impl Credential {
    pub fn new(cert_details: &PKIVaultCertDetails) -> Result<Self> {
        // Private keys for CA, Server, and Client
        let ca_private_key = PKey::generate_ed25519()?;
        let server_private_key = PKey::generate_ed25519()?;
        let client_private_key = PKey::generate_ed25519()?;

        // Generate CA certificate
        let ca_cert = Self::generate_ca_cert(&ca_private_key, cert_details)?;

        // Generate certificate for Server
        let server_cert = Self::generate_signed_cert(
            &server_private_key,
            &ca_cert,
            &ca_private_key,
            cert_details,
            "server",
        )?;

        // Generate certificate for Client
        let client_cert = Self::generate_signed_cert(
            &client_private_key,
            &ca_cert,
            &ca_private_key,
            cert_details,
            "client",
        )?;

        Ok(Self {
            ca_cert: ca_cert.to_pem()?,
            server_key: server_private_key.private_key_to_pem_pkcs8()?,
            server_cert: server_cert.to_pem()?,
            client_key: client_private_key.private_key_to_pem_pkcs8()?,
            client_cert: client_cert.to_pem()?,
        })
    }

    fn generate_signed_cert(
        private_key: &PKey<Private>,
        ca_cert: &X509,
        ca_private_key: &PKey<Private>,
        cert_details: &PKIVaultCertDetails,
        server_or_client: &str,
    ) -> Result<X509> {
        // Check if the certificate is for server or client
        let (common_name, validity_days) = if server_or_client == "server" {
            (
                &cert_details.server.common_name,
                cert_details.server.validity_days,
            )
        } else {
            (
                &cert_details.client.common_name,
                cert_details.client.validity_days,
            )
        };

        // Build the x509 name
        let name = Self::build_x509_name(
            common_name,
            &cert_details.country,
            &cert_details.state,
            &cert_details.locality,
            &cert_details.organization,
            &cert_details.org_unit,
        )?;

        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_version(2)?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(ca_cert.subject_name())?;
        x509_builder.set_pubkey(private_key)?;

        let serial_number = BigNum::from_u32(2)?.to_asn1_integer()?;
        x509_builder.set_serial_number(&serial_number)?;
        x509_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        x509_builder.set_not_after(Asn1Time::days_from_now(validity_days)?.as_ref())?;

        // Add extensions from the certificate extensions file
        x509_builder.append_extension(BasicConstraints::new().critical().build()?)?;
        x509_builder.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        x509_builder.append_extension(
            SubjectKeyIdentifier::new().build(&x509_builder.x509v3_context(None, None))?,
        )?;
        x509_builder.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&x509_builder.x509v3_context(Some(ca_cert), None))?,
        )?;

        x509_builder.sign(ca_private_key, MessageDigest::null())?;
        Ok(x509_builder.build())
    }

    fn generate_ca_cert(
        ca_private_key: &PKey<Private>,
        cert_details: &PKIVaultCertDetails,
    ) -> Result<X509> {
        // Build the x509 name
        let name = Self::build_x509_name(
            &cert_details.ca.common_name,
            &cert_details.country,
            &cert_details.state,
            &cert_details.locality,
            &cert_details.organization,
            &cert_details.org_unit,
        )?;

        // Build the X.509 certificate
        let mut x509_builder = X509Builder::new()?;
        x509_builder.set_subject_name(&name)?;
        x509_builder.set_issuer_name(&name)?;
        x509_builder.set_pubkey(ca_private_key)?;

        // Set certificate validity period
        x509_builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        x509_builder
            .set_not_after(Asn1Time::days_from_now(cert_details.ca.validity_days)?.as_ref())?;

        // Sign the certificate
        x509_builder.sign(ca_private_key, MessageDigest::null())?;
        Ok(x509_builder.build())
    }

    fn build_x509_name(
        common_name: &str,
        country: &str,
        state: &str,
        locality: &str,
        organization: &str,
        org_unit: &str,
    ) -> Result<X509Name> {
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
}
