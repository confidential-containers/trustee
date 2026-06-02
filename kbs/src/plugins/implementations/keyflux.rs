// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::{anyhow, bail, Error, Result};
use std::sync::RwLock;
use std::{collections::HashMap, collections::HashSet, sync::Arc};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{
    extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    X509Builder, X509Name, X509NameBuilder, X509,
};
use serde::{Deserialize, Serialize};

use super::super::plugin_manager::ClientPlugin;

/// Default certificate details if not configured
pub const DEFAULT_COUNTRY: &str = "AA";
pub const DEFAULT_STATE: &str = "Default State";
pub const DEFAULT_LOCALITY: &str = "Default City";
pub const DEFAULT_ORGANIZATION: &str = "Default Organization";
pub const DEFAULT_ORG_UNIT: &str = "Default Unit";
pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 3650;
pub const DEFAULT_SERVER_VALIDITY_DAYS: u32 = 180;
pub const DEFAULT_CLIENT_VALIDITY_DAYS: u32 = 180;

pub const CA_DEFAULT_COMMON_NAME: &str = "KeyFluxCA";

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct KeyFluxPluginConfig {
    #[serde(default)]
    pub keyflux: KeyFluxSection,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct QueryConfig {
    #[serde(default)]
    pub required: Vec<String>,

    #[serde(default)]
    pub spec: Option<SpecConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SpecConfig {
    #[serde(default)]
    pub required: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct LimitsConfig {
    pub symmetric_key_size: usize,
    pub rsa_bits: usize,
    pub allow_types: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[derive(Default)]
pub struct KeyFluxSection {
    #[serde(default)]
    pub ca: TlsCertDetails,

    #[serde(default)]
    pub query: QueryConfig,

    #[serde(default)]
    pub limits: LimitsConfig,
}

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SecretType {
    Tls,
    Symmetric,
    Ed25519,
    Rsa,
}

#[derive(Deserialize)]
struct CertDetailsWrapper {
    client: Option<TlsCertDetails>,
    server: Option<TlsCertDetails>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(default)]
pub struct TlsCertDetails {
    pub country: String,
    pub state: String,
    pub locality: String,
    pub organization: String,
    pub org_unit: String,
    pub common_name: String,
    pub validity_days: u32,
}

impl Default for TlsCertDetails {
    fn default() -> Self {
        Self {
            country: DEFAULT_COUNTRY.to_string(),
            state: DEFAULT_STATE.to_string(),
            locality: DEFAULT_LOCALITY.to_string(),
            organization: DEFAULT_ORGANIZATION.to_string(),
            org_unit: DEFAULT_ORG_UNIT.to_string(),
            common_name: "NOT_SET".to_string(),
            validity_days: DEFAULT_CA_VALIDITY_DAYS,
        }
    }
}

impl TlsCertDetails {
    pub fn builder() -> Self {
        Default::default()
    }

    pub fn common_name(mut self, name: impl Into<String>) -> Self {
        self.common_name = name.into();
        self
    }
}

impl Default for KeyFluxPluginConfig {
    fn default() -> Self {
        Self {
            keyflux: KeyFluxSection {
                //secrets: vec![],
                ca: TlsCertDetails::default(),
                query: QueryConfig::default(),
                limits: LimitsConfig::default(),
            }
        }
    }
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            required: vec![
                "id".to_string(),
            ],
            spec: Some(SpecConfig::default()),
        }
    }
}

impl Default for SpecConfig {
    fn default() -> Self {
        Self {
            required: true,
        }
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            symmetric_key_size: 32,
            rsa_bits: 2048,
            allow_types: vec![
                "tls".to_string(),
                "symmetric".to_string(),
                "ed25519".to_string(),
                "rsa".to_string(),
            ],
        }
    }
}

impl TryFrom<KeyFluxPluginConfig> for KeyFluxPlugin {
    type Error = Error;

    fn try_from(config: KeyFluxPluginConfig) -> Result<Self> {
        Ok(KeyFluxPlugin {
            ca_config: config.keyflux.ca,
            query_config: config.keyflux.query,
            limits_config: config.keyflux.limits,

            spec_store: Arc::new(RwLock::new(HashMap::new())),

            server_cert_config_store: Arc::new(RwLock::new(HashMap::new())),
            client_cert_config_store: Arc::new(RwLock::new(HashMap::new())),

            ca_store: Arc::new(RwLock::new(HashMap::new())),

            ed25519_store: Arc::new(RwLock::new(HashMap::new())),
            rsa_store: Arc::new(RwLock::new(HashMap::new())),
            symkey_store: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyFluxCA {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
}

impl KeyFluxCA {
    pub fn new(cert_details: &TlsCertDetails) -> Result<Self> {
        let key = PKey::generate_ed25519()?;
        let cert = Self::generate_ca_cert(&key, cert_details)?;

        Ok(Self {
            key: key.private_key_to_pem_pkcs8()?,
            cert: cert.to_pem()?,
        })
    }

    /// Init KeyFluxCA with existing key and cert
    pub fn init(key: Vec<u8>, cert: Vec<u8>) -> Result<Self> {
        let _ = PKey::private_key_from_pem(&key)?;
        let _ = X509::from_pem(&cert)?;

        Ok(Self { key, cert })
    }

    /// Generate private key and certificate
    fn generate_credentials(
        &self,
        ca_cert: &X509,
        ca_private_key: &PKey<Private>,
        cert_details: &TlsCertDetails,
    ) -> Result<(PKey<Private>, X509)> {
        let key = PKey::generate_ed25519()?;
        let cert = Self::generate_signed_cert(
            &key,
            &ca_cert,
            &ca_private_key,
            cert_details,
        )?;

        Ok((key, cert))
    }

    /// Generate signed certificate
    fn generate_signed_cert(
        private_key: &PKey<Private>,
        ca_cert: &X509,
        ca_private_key: &PKey<Private>,
        cert_details: &TlsCertDetails,
    ) -> Result<X509> {
        // Build the x509 name
        let name = Self::build_x509_name(
            &cert_details.common_name,
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
        x509_builder.set_not_after(Asn1Time::days_from_now(cert_details.validity_days)?.as_ref())?;

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

    /// Generate CA certificate
    fn generate_ca_cert(
        ca_private_key: &PKey<Private>,
        cert_details: &TlsCertDetails,
    ) -> Result<X509> {
        // Build the x509 name
        let name = Self::build_x509_name(
            &cert_details.common_name,
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
            .set_not_after(Asn1Time::days_from_now(cert_details.validity_days)?.as_ref())?;

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

/// Credentials necessary for secure server-client communication
#[derive(Debug, serde::Serialize)]
pub struct CredentialsOut {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
    pub ca_cert: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SecretBundle {
    pub entity: String,
    pub secrets: HashMap<String, SecretMaterial>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum SecretMaterial {
    Tls {
        private_key: Vec<u8>,
        cert: Vec<u8>,
        ca_cert: Vec<u8>,
    },
    Symmetric {
        key: Vec<u8>,
    },
    Ed25519 {
        key: Vec<u8>,
    },
    Rsa {
        key: Vec<u8>,
    },
}

/// Generates different secrets (tls, symmetric, rsa, ed255519, etc.) on the 
/// fly for kata agent (server) and owner (client)
pub struct KeyFluxPlugin {
    pub ca_config: TlsCertDetails,
    pub query_config: QueryConfig,
    pub limits_config: LimitsConfig,

    // store secret specs
    pub spec_store: Arc<RwLock<HashMap<String, HashMap<SecretType, usize>>>>,

    // store the CAs
    pub ca_store: Arc<RwLock<HashMap<String, KeyFluxCA>>>,

    pub server_cert_config_store: Arc<RwLock<HashMap<String, TlsCertDetails>>>,
    pub client_cert_config_store: Arc<RwLock<HashMap<String, TlsCertDetails>>>,

    // Ed25519 pub key store for clients
    pub ed25519_store: Arc<RwLock<HashMap<String, HashMap<String, Vec<u8>>>>>,

    // Rsa pub key store for clients
    pub rsa_store: Arc<RwLock<HashMap<String, HashMap<String, Vec<u8>>>>>,

    // secret stored for clients
    pub symkey_store: Arc<RwLock<HashMap<String, HashMap<String, Vec<u8>>>>>,
}

impl KeyFluxPlugin {
    ///construct an identifier using query params
    fn construct_key(&self, params: &HashMap<String, String>) -> String {
        self.query_config
            .required
            .iter()
            .map(|k| params.get(k).unwrap())
            .cloned()
            .collect::<Vec<_>>()
            .join("_")
    }

    fn validate_query(&self, query: &HashMap<String, String>) -> Result<()> {
        let cfg = &self.query_config;
        for key in &cfg.required {
            if !query.contains_key(key) {
                bail!("Missing required query parameter: {}", key);
            }

            if query.get(key).map(|v| v.trim().is_empty()).unwrap_or(true) {
                bail!("Query parameter '{}' cannot be empty", key);
            }
        }

        Ok(())
    }

    fn parse_spec(spec: &str) -> Result<HashMap<SecretType, usize>> {
        let mut result = HashMap::new();

        for item in spec.split(';') {
            let parts: Vec<&str> = item.split(':').collect();

            if parts.len() != 2 {
                return Err(anyhow!("Invalid spec format: {}", item));
            }

            let secret_type = match parts[0] {
                "tls" => SecretType::Tls,
                "sym" | "symmetric" => SecretType::Symmetric,
                "pkey" | "ed25519" => SecretType::Ed25519,
                "rsa" => SecretType::Rsa,
                other => return Err(anyhow!("Unknown secret type: {}", other)),
            };

            let count: usize = parts[1]
                .parse()
                .map_err(|_| anyhow!("Invalid count for {}", parts[0]))?;

            if count == 0 {
                return Err(anyhow!("Count must be > 0 for {}", parts[0]));
            }

            result.insert(secret_type, count);
        }

        Ok(result)
    }

    fn get_ca(&self, key: &str) -> Option<KeyFluxCA> {
        let store = self.ca_store.read().unwrap();
        store.get(key).cloned()
    }

    fn store_ca(&self, key: &str, ca: KeyFluxCA) {
        let mut store = self.ca_store.write().unwrap();
        store.insert(key.to_string(), ca);
    }

    fn get_symkey(&self, req_id: &str, spec_id: &str) -> Option<Vec<u8>> {
        let store = self.symkey_store.read().unwrap();
        store
            .get(req_id)
            .and_then(|inner| inner.get(spec_id))
            .cloned()
    }

    fn store_symkey(&self, req_id: &str, spec_id: &str, symkey: Vec<u8>) {
        let mut store = self.symkey_store.write().unwrap();
        let inner_map = store
            .entry(req_id.to_string())
            .or_insert_with(HashMap::new);

        inner_map.insert(spec_id.to_string(), symkey);
    }

    fn get_ed25519_pkey(&self, req_id: &str, spec_id: &str) -> Option<Vec<u8>> {
        let store = self.ed25519_store.read().unwrap();
        store
            .get(req_id)
            .and_then(|inner| inner.get(spec_id))
            .cloned()
    }

    fn store_ed25519_pkey(&self, req_id: &str, spec_id: &str, key: Vec<u8>) {
        let mut store = self.ed25519_store.write().unwrap();
        let inner_map = store
            .entry(req_id.to_string())
            .or_insert_with(HashMap::new);

        inner_map.insert(spec_id.to_string(), key);
    }

    fn get_rsa_pkey(&self, req_id: &str, spec_id: &str) -> Option<Vec<u8>> {
        let store = self.rsa_store.read().unwrap();
        store
            .get(req_id)
            .and_then(|inner| inner.get(spec_id))
            .cloned()
    }

    fn store_rsa_pkey(&self, req_id: &str, spec_id: &str, key: Vec<u8>) {
        let mut store = self.rsa_store.write().unwrap();
        let inner_map = store
            .entry(req_id.to_string())
            .or_insert_with(HashMap::new);

        inner_map.insert(spec_id.to_string(), key);
    }

    async fn build_server_response(&self, 
        query: &HashMap<String, String>,
        ) -> Result<Vec<u8>> {
        self.validate_query(query)?;
        let req_id = self.construct_key(query);

        let spec_str = query
            .get("spec")
            .ok_or_else(|| anyhow!("Missing spec"))?;

        let spec_map = Self::parse_spec(spec_str)?;
        self.spec_store.write().unwrap().insert(req_id.clone(), spec_map.clone());

        let mut server_secrets_map: HashMap<String, SecretMaterial> = HashMap::new();

        for (secret_type, count) in spec_map {
            match secret_type {
                SecretType::Tls => {
                    let ca = match self.get_ca(&req_id) {
                        Some(c) => KeyFluxCA::init(c.key, c.cert)?,
                        None => {
                            let ca = KeyFluxCA::new(&self.ca_config)?;
                            self.store_ca(&req_id, ca.clone());
                            ca
                        }
                    };
                    let ca_cert = X509::from_pem(&ca.cert)?;
                    let ca_key = PKey::private_key_from_pem(&ca.key)?;

                    // generate server Tls secrets
                    let ka_config = self.server_cert_config_store.read().unwrap()
                        .get(&req_id)
                        .cloned()
                        .unwrap_or_else(|| TlsCertDetails::builder().common_name("Kata Agent"));

                    for i in 0..count {
                        let server_spec_id = format!("{}_{}", "tls", i);
                        let (key, cert) = ca.generate_credentials(
                            &ca_cert,
                            &ca_key,
                            &ka_config,
                        )?;
                        server_secrets_map.insert(
                            server_spec_id,
                            SecretMaterial::Tls {
                                private_key: key.private_key_to_pem_pkcs8()?,
                                cert: cert.to_pem()?,
                                ca_cert: ca.cert.clone(),
                            },
                        );
                    }
                }
                SecretType::Symmetric => {
                    //let size = spec.size.unwrap_or(32) as usize;
                    let size: usize = 32;

                    for i in 0..count {
                        let mut key = vec![0u8; size];
                        openssl::rand::rand_bytes(&mut key)?;

                        let sym_id = format!("{}_{}", "sym", i);
                        server_secrets_map.insert(
                            sym_id.clone(),
                            SecretMaterial::Symmetric { key: key.clone() },
                        );
                        self.store_symkey(&req_id, &sym_id, key);
                    }
                }
                SecretType::Ed25519 => {
                    for i in 0..count {
                        let key = PKey::generate_ed25519()?;

                        let private_key = key.private_key_to_pem_pkcs8()?;
                        let public_key = key.public_key_to_pem()?;

                        let spec_id = format!("{}_{}", "ed25519_key", i);

                        server_secrets_map.insert(
                            spec_id.clone(),
                            SecretMaterial::Ed25519 {
                                key: private_key.clone(),
                            },
                        );

                        self.store_ed25519_pkey(&req_id, &spec_id, public_key);
                    }
                }
                SecretType::Rsa => {
                    let bits: u32 = 2048;

                    for i in 0..count {
                        let rsa = Rsa::generate(bits)?;
                        let key = PKey::from_rsa(rsa)?;

                        let private_key_pem = key.private_key_to_pem_pkcs8()?;
                        let public_key_pem = key.public_key_to_pem()?;

                        let spec_id = format!("{}_{}", "rsa_key", i);

                        server_secrets_map.insert(
                            spec_id.clone(),
                            SecretMaterial::Rsa {
                                key: private_key_pem.clone(),
                            },
                        );

                        self.store_rsa_pkey(&req_id, &spec_id, public_key_pem);
                    }
                }
            }
        }

        let bundle = SecretBundle {
            entity: "server".to_string(),
            secrets: server_secrets_map,
        };

        Ok(serde_json::to_vec(&bundle)?)
    }

    async fn list_pods(&self) -> Result<Vec<u8>> {
        let all_keys: Vec<String> = {
            let mut keys = HashSet::new();
            keys.extend(self.ca_store.read().unwrap().keys().cloned());
            keys.extend(self.ed25519_store.read().unwrap().keys().cloned());
            keys.extend(self.rsa_store.read().unwrap().keys().cloned());
            keys.extend(self.symkey_store.read().unwrap().keys().cloned());

            keys.into_iter().collect()
        };

        Ok(serde_json::to_vec(&all_keys)?)
    }

    async fn build_client_response(&self, 
        query: &HashMap<String, String>,
        ) -> Result<Vec<u8>> {
        self.validate_query(query)?;
        let req_id = self.construct_key(query);

        let mut client_secrets_map: HashMap<String, SecretMaterial> = HashMap::new();

        // retrieve the saved spec map from hashmap
        let spec_map = {
            let store = self.spec_store.read().unwrap();
            store.get(&req_id)
                .cloned()
                .ok_or_else(|| anyhow!("Spec not found for req_id: {}", req_id))?
        };

        for (secret_type, count) in spec_map {
            match secret_type {
                SecretType::Tls => {
                    // get existing CA, else return error
                    let ca = self
                        .get_ca(&req_id)
                        .ok_or_else(|| anyhow!("CA not found for sandbox: {}", req_id))?;

                    let ca_cert = X509::from_pem(&ca.cert)?;
                    let ca_key = PKey::private_key_from_pem(&ca.key)?;

                    // client Tls secrets
                    let client_config = self.client_cert_config_store.read().unwrap()
                        .get(&req_id)
                        .cloned()
                        .unwrap_or_else(|| TlsCertDetails::builder().common_name("Client"));

                    for i in 0..count {
                        let (key, cert) = ca.generate_credentials(
                            &ca_cert,
                            &ca_key,
                            &client_config,
                        )?;

                        client_secrets_map.insert(
                            format!("tls_{}", i),
                            SecretMaterial::Tls {
                                private_key: key.private_key_to_pem_pkcs8()?,
                                cert: cert.to_pem()?,
                                ca_cert: ca.cert.clone(),
                            },
                        );
                    }
                }
                SecretType::Symmetric => {
                    for i in 0..count {
                        let sym_id = format!("{}_{}", "sym", i);
                        let key = self
                            .get_symkey(&req_id, &sym_id)
                            .ok_or_else(|| anyhow::anyhow!("Symmetric key not found for spec_id={}",
                                sym_id
                            ))?;

                        client_secrets_map.insert(
                            sym_id.clone(),
                            SecretMaterial::Symmetric { key: key.clone() },
                        );
                    }
                }
                SecretType::Ed25519 => {
                    for i in 0..count {
                        let spec_id = format!("{}_{}", "ed25519_key", i);
                        let key = self
                            .get_ed25519_pkey(&req_id, &spec_id)
                            .ok_or_else(|| anyhow::anyhow!("Ed25519 public key not found for spec_id={}",
                                spec_id
                            ))?;

                        client_secrets_map.insert(
                            spec_id.clone(),
                            SecretMaterial::Ed25519 { key: key.clone() },
                        );
                    }
                }
                SecretType::Rsa => {
                    for i in 0..count {
                        let spec_id = format!("{}_{}", "rsa_key", i);
                        let key = self
                            .get_rsa_pkey(&req_id, &spec_id)
                            .ok_or_else(|| anyhow::anyhow!("RSA public key not found for spec_id={}",
                                spec_id
                            ))?;

                        client_secrets_map.insert(
                            spec_id.clone(),
                            SecretMaterial::Rsa { key: key.clone() },
                        );
                    }
                }
            }
        }

        let bundle = SecretBundle {
            entity: "client".to_string(),
            secrets: client_secrets_map,
        };

        Ok(serde_json::to_vec(&bundle)?)
    }
    async fn update_cert_details(&self,
        query: &HashMap<String, String>,
        data: &[u8],
    ) -> Result<()> {
        self.validate_query(query)?;
        let req_id = self.construct_key(query);

        let wrapper: CertDetailsWrapper = serde_json::from_slice(data)
            .map_err(|e| anyhow!("Failed to deserialize JSON: {}", e))?;

        // update server cert details
        if let Some(updates) = wrapper.server {
            let mut store = self.server_cert_config_store.write().unwrap();

            store.entry(req_id.clone())
                .and_modify(|existing| {
                    *existing = updates.clone();
                })
            .or_insert(updates);
        }

        // update client cert details
        if let Some(updates) = wrapper.client {
            let mut store = self.client_cert_config_store.write().unwrap();

            store.entry(req_id.clone())
                .and_modify(|existing| {
                    *existing = updates.clone();
                })
            .or_insert(updates);
        } 

        Ok(())
    }
}

#[async_trait::async_trait]
impl ClientPlugin for KeyFluxPlugin {
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
    ) -> Result<Vec<u8>> {
        if path.len() != 1 {
            bail!("Illegal path. Only one path segment is supported");
        }

        match method.as_str() {
            "GET" => match path[0] {
                "credentials" => {
                    let credentials = self.build_server_response(query).await?;
                    Ok(credentials)
                }
                _ => Err(anyhow!("{} not supported", path[0]))?,
            }
            "POST" => match path[0] {
                "list_pods" => {
                    let pods = self.list_pods().await?;
                    Ok(pods)
                }
                "client_creds" => {
                    let credentials = self.build_client_response(query).await?;
                    Ok(credentials)
                }
                "update_cert" => {
                    self.update_cert_details(query, body).await?;
                    Ok(vec![])
                }
                _ => Err(anyhow!("{} not supported", path[0]))?,
            }
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "POST" {
            return Ok(true);
        }

        Ok(false)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "GET" {
            return Ok(true);
        }

        Ok(false)
    }
}
