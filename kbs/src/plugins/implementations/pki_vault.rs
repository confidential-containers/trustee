// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Error, Result};
use std::sync::RwLock;
use std::{collections::HashMap, fs, path::PathBuf, sync::Arc};

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

const DEFAULT_PLUGIN_DIR: &str = "/opt/confidential-containers/kbs/plugin/pki_vault";
const DEFAULT_CREDENTIALS_BLOB_FILE: &str = "certificates.json";

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
pub struct Credentials {
    pub ca_cert: Vec<u8>,
    pub server_key: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub client_key: Vec<u8>,
    pub client_cert: Vec<u8>,
}

impl Credentials {
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


#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct PKIVaultPluginConfig {
    pub plugin_dir: String,
    pub cred_filename: String,
    pub pkivault_cert_details: PKIVaultCertDetails,
}

impl Default for PKIVaultPluginConfig {
    fn default() -> Self {
        PKIVaultPluginConfig {
            plugin_dir: DEFAULT_PLUGIN_DIR.into(),
            cred_filename: DEFAULT_CREDENTIALS_BLOB_FILE.into(),
            pkivault_cert_details: PKIVaultCertDetails::default(),
        }
    }
}

impl TryFrom<PKIVaultPluginConfig> for PKIVaultPlugin {
    type Error = Error;

    fn try_from(config: PKIVaultPluginConfig) -> Result<Self> {
        // Create the plugin dir if it does not exist
        let plugin_dir = PathBuf::from(&config.plugin_dir);
        if !plugin_dir.exists() {
            fs::create_dir_all(&plugin_dir)?;
            log::info!("plugin dir created = {}", plugin_dir.display());
        }

        // Read the existing credentials from file
        let path = PathBuf::from(&config.plugin_dir)
            .as_path()
            .join(config.cred_filename);

        let credential: HashMap<String, Credentials> = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(data) => serde_json::from_str(&data).unwrap_or_else(|_| HashMap::new()),
                Err(_) => {
                    log::warn!("Error reading the credentials file.");
                    HashMap::new()
                }
            }
        } else {
            log::warn!("Credentails file does not exist.");
            HashMap::new()
        };

        // Initializing the PKI Vault plugin with existing credentials data from file
        Ok(PKIVaultPlugin {
            plugin_dir: PathBuf::from(&config.plugin_dir),
            cert_details: config.pkivault_cert_details,
            credblob_file: path,
            cred_store: Arc::new(RwLock::new(credential)),
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
    /// Required: ID of a sandbox or pod
    pub id: String,

    /// Required: IP of a sandbox or pod
    pub ip: String,

    /// Required: Name of a sandbox or pod
    pub name: String,
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
    pub plugin_dir: PathBuf,
    pub cert_details: PKIVaultCertDetails,
    pub credblob_file: PathBuf,
    pub cred_store: Arc<RwLock<HashMap<String, Credentials>>>,
}

impl PKIVaultPlugin {
    fn get_credentials(&self, key: &str) -> Option<Credentials> {
        let cred_store = self.cred_store.read().unwrap();
        cred_store.get(key).cloned()
    }

    fn store_credentials(&self, key: &str, credentials: Credentials) {
        let mut cred_store = self.cred_store.write().unwrap();
        cred_store.insert(key.to_string(), credentials);
    }

    // Generate the credentials (keys and certs for ca, server, and client)
    fn generate_credentials(&self, key: &str) -> Result<Vec<u8>> {
        let credentials = Credentials::new(&self.cert_details)?;

        // Store the credentials into the hashmap
        self.store_credentials(key, credentials.clone());

        // Write the hashmap to file for a persistence copy
        if let Err(e) = self.save_hashmap(&self.credblob_file) {
            log::warn!("Failed to store credentials into file: {}", e);
        }

        log::info!("Returning newly generated credentials!");
        let resource = CredentialsOut {
            key: credentials.server_key.clone(),
            cert: credentials.server_cert.clone(),
            ca_cert: credentials.ca_cert.clone(),
        };

        Ok(serde_json::to_vec(&resource)?)
    }

    fn save_hashmap(&self, path: &PathBuf) -> Result<()> {
        let cred_store = self.cred_store.read().unwrap();
        let serialized = serde_json::to_string(&*cred_store)?;
        fs::write(path, serialized)?;
        Ok(())
    }

    async fn get_server_credentials(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        // Return the server credentials if the credentials presents in the hashmap
        let key = format!("{}_{}_{}", &params.name, &params.ip, &params.id);
        if let Some(credentials) = self.get_credentials(&key) {
            log::info!("Returning existing credentials!");

            let resource = CredentialsOut {
                key: credentials.server_key,
                cert: credentials.server_cert,
                ca_cert: credentials.ca_cert,
            };

            return Ok(serde_json::to_vec(&resource)?);
        };

        // Otherwise return newly generated credentials
        self.generate_credentials(&key)
    }

    async fn list_pods(&self) -> Result<Vec<u8>> {
        let cred_store = self.cred_store.read().unwrap();
        let keys: Vec<String> = cred_store.keys().cloned().collect();
        Ok(serde_json::to_vec(&keys).expect("Failed to deserialize it!"))
    }

    async fn get_client_credentials(&self, params: &SandboxParams) -> Result<Vec<u8>> {
        let key = format!("{}_{}_{}", &params.name, &params.ip, &params.id);
        if let Some(credentials) = self.get_credentials(&key) {
            log::info!("Found client credentials!");

            let resource = CredentialsOut {
                key: credentials.client_key,
                cert: credentials.client_cert,
                ca_cert: credentials.ca_cert,
            };

            return Ok(serde_json::to_vec(&resource)?);
        };

        return Ok(serde_json::to_vec("")?);
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
            "GET" => {
                match sub_path {
                    "credentials" => {
                        let params = SandboxParams::try_from(query)?;
                        let credentials = self.get_server_credentials(&params).await?;

                        Ok(credentials)
                    }
                    "list_pods" => {
                        let pods = self.list_pods().await?;

                        Ok(pods)
                    }
                    "get_client_credentials" => {
                        let params = SandboxParams::try_from(query)?;
                        let credentials = self.get_client_credentials(&params).await?;

                        Ok(credentials)
                    }
                    _ => Err(anyhow!("{} not supported", sub_path))?,
                }
            }
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
        let query = "id=3367348&ip=60.11.12.43&name=pod7";
        let path = "/credentials";
        let method = &Method::GET;

        // Act: call the handle method
        let result = plugin.handle(body, query, path, method).await;

        // Assert: check the result
        match result {
            Ok(response) => {
                // Expected results
                let key = String::from("pod7_60.11.12.43_3367348");

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