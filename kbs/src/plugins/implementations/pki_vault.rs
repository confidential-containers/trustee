// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Error, Result};
use std::sync::RwLock;
use std::{collections::HashMap, sync::Arc};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::x509::{
    extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    X509Builder, X509Name, X509NameBuilder, X509,
};
use serde::{Deserialize, Serialize};

use crate::plugins::plugin_manager::ClientPlugin;

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

/// Credentials necessary for mutual TLS communication
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PKIVaultCA {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
}

impl PKIVaultCA {
    pub fn new(cert_details: &PKIVaultCertDetails) -> Result<Self> {
        // Private keys for CA, Server, and Client
        let key = PKey::generate_ed25519()?;

        // Generate CA certificate
        let cert = Self::generate_ca_cert(&key, cert_details)?;

        Ok(Self {
            key: key.private_key_to_pem_pkcs8()?,
            cert: cert.to_pem()?,
        })
    }

    /// Initializes a PKIVaultCA from existing key and certificate bytes.
    pub fn init(key: Vec<u8>, cert: Vec<u8>) -> Result<Self> {
        // Optional: Validate that the key and cert are valid before returning
        let _ = PKey::private_key_from_pem(&key)?;
        let _ = X509::from_pem(&cert)?;

        Ok(Self { key, cert })
    }

    fn generate_credentials(
        &self,
        ca_cert: &X509,
        ca_private_key: &PKey<Private>,
        cert_details: &PKIVaultCertDetails,
        for_podvm_or_owner: &str,
    ) -> Result<(PKey<Private>, X509)> {
        // Generate private key and certificate
        let key = PKey::generate_ed25519()?;
        let cert = Self::generate_signed_cert(
            &key,
            &ca_cert,
            &ca_private_key,
            cert_details,
            for_podvm_or_owner,
        )?;

        Ok((key, cert))
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

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct PKIVaultPluginConfig {
    pub pkivault_cert_details: PKIVaultCertDetails,
}

impl Default for PKIVaultPluginConfig {
    fn default() -> Self {
        PKIVaultPluginConfig {
            pkivault_cert_details: PKIVaultCertDetails::default(),
        }
    }
}

impl TryFrom<PKIVaultPluginConfig> for PKIVaultPlugin {
    type Error = Error;

    fn try_from(config: PKIVaultPluginConfig) -> Result<Self> {
        let empty_cas: HashMap<String, PKIVaultCA> = HashMap::new();

        // Initializing the PKI Vault plugin with existing credentials data from file
        Ok(PKIVaultPlugin {
            cert_details: config.pkivault_cert_details,
            ca_store: Arc::new(RwLock::new(empty_cas)),
        })
    }
}

/// Parameters for the credentials request
///
/// These parameters are provided in the request via URL query string.
/// Parameters taken by the "pki-vault" plugin to generate a unique key
/// for a sandbox store and retrieve credentials specific to the sandbox.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct SandboxParams {
    /// Required: Token assigned to the Pod
    pub token: String,

    /// Required: Pod name (unique within a namespace)
    pub name: String,

    /// Required: Pod IP address
    pub ip: String,
}

impl TryFrom<&str> for SandboxParams {
    type Error = Error;

    fn try_from(query: &str) -> Result<Self> {
        let params: SandboxParams = serde_qs::from_str(query)?;
        Ok(params)
    }
}

/// Credentials necessary for secure server-client communication
#[derive(Debug, serde::Serialize)]
pub struct CredentialsOut {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

/// Manages the credentials generation, handling requests
/// from backend, and credentials persistence storage
pub struct PKIVaultPlugin {
    pub cert_details: PKIVaultCertDetails,
    pub ca_store: Arc<RwLock<HashMap<String, PKIVaultCA>>>,
}

impl PKIVaultPlugin {
    fn construct_key(&self, params: &SandboxParams) -> String {
        format!("{}_{}_{}", params.name, params.ip, params.token)
    }

    fn get_ca(&self, key: &str) -> Option<PKIVaultCA> {
        let ca_store = self.ca_store.read().unwrap();
        ca_store.get(key).cloned()
    }

    fn store_ca(&self, key: &str, ca: PKIVaultCA) {
        let mut ca_store = self.ca_store.write().unwrap();
        ca_store.insert(key.to_string(), ca);
    }

    async fn generate_pod_credentials(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        let key = self.construct_key(&params);

        // Return the stored CA credentials if they are present in the hashmap
        let ca = if let Some(stored_ca) = self.get_ca(&key) {
            log::info!("Generating credentials using existing CA!");
            PKIVaultCA::init(stored_ca.key, stored_ca.cert)?
        } else {
            log::info!("Generating credentials using new CA!");
            let new_ca = PKIVaultCA::new(&self.cert_details)?;

            // Store the newly created CA for future use
            self.store_ca(&key, new_ca.clone());

            new_ca
        };

        let (pod_key, pod_cert) = ca.generate_credentials(
            &X509::from_pem(&ca.cert)?,
            &PKey::private_key_from_pem(&ca.key)?,
            &self.cert_details,
            "server",
        )?;

        let resource = CredentialsOut {
            key: pod_key.private_key_to_pem_pkcs8()?,
            cert: pod_cert.to_pem()?,
            ca_cert: ca.cert,
        };

        Ok(serde_json::to_vec(&resource)?)
    }

    async fn list_pods(&self) -> Result<Vec<u8>> {
        let ca_store = self.ca_store.read().unwrap();
        let keys: Vec<String> = ca_store.keys().cloned().collect();
        Ok(serde_json::to_vec(&keys).expect("Failed to deserialize it!"))
    }

    async fn generate_client_credentials(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        let key_hash = self.construct_key(&params);

        // Return the stored CA credentials if they are present in the hashmap
        if let Some(stored_ca) = self.get_ca(&key_hash) {
            log::info!("Returning client credentials!");

            let ca = PKIVaultCA::init(stored_ca.key, stored_ca.cert)?;

            let (pod_key, pod_cert) = ca.generate_credentials(
                &X509::from_pem(&ca.cert)?,
                &PKey::private_key_from_pem(&ca.key)?,
                &self.cert_details,
                "server",
            )?;

            let resource = CredentialsOut {
                key: pod_key.private_key_to_pem_pkcs8()?,
                cert: pod_cert.to_pem()?,
                ca_cert: ca.cert,
            };

            return Ok(serde_json::to_vec(&resource)?);
        } else {
            log::info!("Credentails cannot be generated. No CA found!");

            return Ok(serde_json::to_vec("")?);
        }
    }
}

#[async_trait::async_trait]
impl ClientPlugin for PKIVaultPlugin {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;

        match method.as_str() {
            "GET" => match sub_path {
                "credentials" => {
                    let params = SandboxParams::try_from(query)?;
                    let credentials = self.generate_pod_credentials(&params).await?;

                    Ok(credentials)
                }
                "list_pods" => {
                    let pods = self.list_pods().await?;

                    Ok(pods)
                }
                "client_credentials" => {
                    let params = SandboxParams::try_from(query)?;
                    let credentials = self.generate_client_credentials(&params).await?;

                    Ok(credentials)
                }
                _ => Err(anyhow!("{} not supported", sub_path))?,
            },
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<bool> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;

        if method.as_str() == "GET" {
            if sub_path != "credentials" {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<bool> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;

        if method.as_str() == "GET" {
            if sub_path == "credentials" {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_handle() {
        let config = PKIVaultPluginConfig::default();
        let plugin = PKIVaultPlugin::try_from(config).unwrap();

        // Define sample inputs
        let body: &[u8] = b"";
        let query = "token=podToken12345&name=pod51&ip=60.11.12.89";
        let path = "/credentials";
        let method = &Method::GET;

        // Act: call the handle method
        let result = plugin.handle(body, query, path, method).await;

        // Assert: check the result
        match result {
            Ok(response) => {
                // Expected results
                let key = String::from("podToken12345_pod51_60.11.12.89");

                if let Some(credentials) = plugin.get_credentials(&key) {
                    let resource = CredentialsOut {
                        key: credentials.server_key,
                        cert: credentials.server_cert,
                        ca_cert: credentials.ca_cert,
                    };

                    let expected_response = serde_json::to_vec(&resource).unwrap();
                    assert_eq!(response, expected_response);
                };
            }
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    }
}
