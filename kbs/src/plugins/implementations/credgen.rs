// Copyright (c) 2026 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};
use key_value_storage::{KeyValueStorageInstance, SetParameters, StorageProvider};
use std::{collections::HashMap, sync::Arc};
use strum::{Display, EnumString};

use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::{
    extension::{AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier},
    X509Builder, X509Name, X509NameBuilder, X509NameRef, X509,
};
use serde::{Deserialize, Serialize};

use super::super::plugin_manager::ClientPlugin;

/// Default X.509 subject fields. `"AA"` is the ISO 3166-1 reserved private-use country code.
pub const DEFAULT_COUNTRY: &str = "AA";
pub const DEFAULT_STATE: &str = "N/A";
pub const DEFAULT_LOCALITY: &str = "N/A";
pub const DEFAULT_ORGANIZATION: &str = "Confidential Containers";
pub const DEFAULT_ORG_UNIT: &str = "Trustee";

/// Validity period for the per-identity CA certificate (days).
pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 365;

/// Validity period for end-entity (server/client) certificates (days).
pub const DEFAULT_CERT_VALIDITY_DAYS: u32 = 90;

// ---- Config types -------------------------------------------------------

/// Query/init-data fields joined with `_` to form the per-identity store key prefix.
/// E.g. `name=pod-abc`, `ns=default` → `"pod-abc_default"`.
pub const IDENTITY_FIELDS: &[&str] = &["name", "ns"];

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct CredGenPluginConfig {
    #[serde(default)]
    pub credgen: CredGenConfig,
}

/// Key-size and allowlist settings.
#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SettingsConfig {
    /// Symmetric key length in bytes.
    pub symmetric_key_size: usize,
    /// RSA key size in bits.
    pub rsa_bits: usize,
    /// Random byte sequence length in bytes.
    pub random_bytes_size: usize,
    /// Allowed `"type/algorithm"` pairs (e.g. `"cert/tls"`, `"asymmetric/ed25519"`).
    /// `"symmetric"` and `"random"` need no algorithm suffix.
    pub supported_types: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct CredGenConfig {
    #[serde(default)]
    pub ca: TlsCertDetails,

    #[serde(default)]
    pub settings: SettingsConfig,
}

// ---- SecretType / Algorithm enums ---------------------------------------

/// High-level secret category (`secret_type` query parameter).
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum SecretType {
    /// X.509 certificate; algorithm selects the specific kind.
    Cert,
    /// Asymmetric key pair; algorithm selects ed25519 or rsa.
    Asymmetric,
    /// Symmetric key (raw random bytes).
    Symmetric,
    /// Opaque random bytes.
    Random,
}

/// Certificate algorithm (`algorithm` param for `secret_type=cert`).
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum CertAlgorithm {
    /// Ed25519 CA-signed bundle: CA cert + server cert + private key.
    Tls,
    /// P-256 (ECDSA) self-signed certificate.
    P256,
}

/// Asymmetric key algorithm (`algorithm` param for `secret_type=asymmetric`).
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum AsymmetricAlgorithm {
    Ed25519,
    Rsa,
}

/// Symmetric key algorithm (`algorithm` param for `secret_type=symmetric`). Defaults to `raw`.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum SymmetricAlgorithm {
    /// Raw random bytes; the caller determines the cipher usage.
    Raw,
}

/// Random bytes algorithm (`algorithm` param for `secret_type=random`). Defaults to `csprng`.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
pub enum RandomAlgorithm {
    /// OpenSSL CSPRNG output.
    Csprng,
}

/// Fully-resolved `(secret_type, algorithm)` pair parsed from the query string.
#[derive(Clone, Debug)]
pub enum SecretSpec {
    Cert(CertAlgorithm),
    Asymmetric(AsymmetricAlgorithm),
    Symmetric(SymmetricAlgorithm),
    Random(RandomAlgorithm),
}

impl SecretSpec {
    /// `secret_type` string used in HTTP responses and store keys.
    pub fn type_str(&self) -> &'static str {
        match self {
            SecretSpec::Cert(_) => "cert",
            SecretSpec::Asymmetric(_) => "asymmetric",
            SecretSpec::Symmetric(_) => "symmetric",
            SecretSpec::Random(_) => "random",
        }
    }

    /// `algorithm` string used in HTTP responses and store keys.
    pub fn algorithm_str(&self) -> String {
        match self {
            SecretSpec::Cert(a) => a.to_string(),
            SecretSpec::Asymmetric(a) => a.to_string(),
            SecretSpec::Symmetric(a) => a.to_string(),
            SecretSpec::Random(a) => a.to_string(),
        }
    }

    /// Key for the `supported_types` allowlist: `"type/algorithm"` or just `"type"`.
    pub fn allowlist_key(&self) -> String {
        match self {
            SecretSpec::Cert(a) => format!("cert/{}", a),
            SecretSpec::Asymmetric(a) => format!("asymmetric/{}", a),
            SecretSpec::Symmetric(_) => "symmetric".to_string(),
            SecretSpec::Random(_) => "random".to_string(),
        }
    }
}

// ---- TLS cert helpers ---------------------------------------------------

#[derive(Deserialize)]
struct CertDetailsWrapper {
    client: Option<TlsCertDetails>,
    server: Option<TlsCertDetails>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    pub fn set_common_name(&mut self, name: impl Into<String>) {
        self.common_name = name.into();
    }

    pub fn set_validity_days(&mut self, days: u32) {
        self.validity_days = days;
    }
}

// ---- Default impls ------------------------------------------------------

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            symmetric_key_size: 32,
            rsa_bits: 2048,
            random_bytes_size: 32,
            supported_types: vec![
                "cert/tls".to_string(),
                "cert/p256".to_string(),
                "asymmetric/ed25519".to_string(),
                "asymmetric/rsa".to_string(),
                "symmetric".to_string(),
                "random".to_string(),
            ],
        }
    }
}

// ---- CredGenCA ----------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CredGenCA {
    pub key: Vec<u8>,
    pub cert: Vec<u8>,
}

impl CredGenCA {
    pub fn new(cert_details: &TlsCertDetails) -> Result<Self> {
        let key = PKey::generate_ed25519()?;
        let cert = Self::generate_ca_cert(&key, cert_details)?;

        Ok(Self {
            key: key.private_key_to_pem_pkcs8()?,
            cert: cert.to_pem()?,
        })
    }

    /// Build a `CredGenCA` from existing PEM-encoded key and certificate (validated on load).
    pub fn init(key: Vec<u8>, cert: Vec<u8>) -> Result<Self> {
        let _ = PKey::private_key_from_pem(&key)?;
        let _ = X509::from_pem(&cert)?;

        Ok(Self { key, cert })
    }

    /// Issue a fresh Ed25519 end-entity key and certificate signed by this CA.
    fn generate_credentials(&self, cert_details: &TlsCertDetails) -> Result<(PKey<Private>, X509)> {
        let ca_cert = X509::from_pem(&self.cert)?;
        let ca_key = PKey::private_key_from_pem(&self.key)?;
        let key = PKey::generate_ed25519()?;
        let cert = Self::generate_signed_cert(&key, &ca_cert, &ca_key, cert_details)?;
        Ok((key, cert))
    }

    /// Return an `X509Builder` pre-filled with version, names, pubkey, and validity.
    /// The caller appends any extra extensions, then calls `sign` + `build`.
    fn init_x509_builder(
        subject: &X509NameRef,
        issuer: &X509NameRef,
        pubkey: &PKey<Private>,
        validity_days: u32,
    ) -> Result<X509Builder> {
        let mut b = X509Builder::new()?;
        b.set_version(2)?;
        b.set_subject_name(subject)?;
        b.set_issuer_name(issuer)?;
        b.set_pubkey(pubkey)?;
        b.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        b.set_not_after(Asn1Time::days_from_now(validity_days)?.as_ref())?;
        Ok(b)
    }

    /// Build a CA-signed X.509 v3 end-entity certificate.
    fn generate_signed_cert(
        private_key: &PKey<Private>,
        ca_cert: &X509,
        ca_private_key: &PKey<Private>,
        cert_details: &TlsCertDetails,
    ) -> Result<X509> {
        let subject = Self::build_x509_name(cert_details)?;

        // Random 8-byte serial per RFC 5280 §4.1.2.2.
        let mut serial_bytes = [0u8; 8];
        openssl::rand::rand_bytes(&mut serial_bytes)?;
        let serial_asn1 = BigNum::from_slice(&serial_bytes)?.to_asn1_integer()?;

        let mut b = Self::init_x509_builder(
            &subject,
            ca_cert.subject_name(),
            private_key,
            cert_details.validity_days,
        )?;
        b.set_serial_number(&serial_asn1)?;
        b.append_extension(BasicConstraints::new().critical().build()?)?;
        b.append_extension(
            KeyUsage::new()
                .digital_signature()
                .key_encipherment()
                .build()?,
        )?;
        b.append_extension(SubjectKeyIdentifier::new().build(&b.x509v3_context(None, None))?)?;
        b.append_extension(
            AuthorityKeyIdentifier::new()
                .keyid(false)
                .issuer(false)
                .build(&b.x509v3_context(Some(ca_cert), None))?,
        )?;
        b.sign(ca_private_key, MessageDigest::null())?;
        Ok(b.build())
    }

    /// Build a self-signed CA certificate.
    fn generate_ca_cert(ca_private_key: &PKey<Private>, cert_details: &TlsCertDetails) -> Result<X509> {
        let name = Self::build_x509_name(cert_details)?;
        let mut b = Self::init_x509_builder(&name, &name, ca_private_key, cert_details.validity_days)?;
        b.sign(ca_private_key, MessageDigest::null())?;
        Ok(b.build())
    }

    /// Build a self-signed P-256 (ECDSA) certificate. Uses SHA-256 digest (unlike Ed25519).
    pub fn generate_p256_self_signed_cert(
        key: &PKey<Private>,
        cert_details: &TlsCertDetails,
    ) -> Result<X509> {
        let name = Self::build_x509_name(cert_details)?;
        let mut b = Self::init_x509_builder(&name, &name, key, cert_details.validity_days)?;
        b.sign(key, MessageDigest::sha256())?;
        Ok(b.build())
    }

    fn build_x509_name(cert_details: &TlsCertDetails) -> Result<X509Name> {
        let mut name_builder = X509NameBuilder::new()?;
        name_builder.append_entry_by_text("C", &cert_details.country)?;
        name_builder.append_entry_by_text("ST", &cert_details.state)?;
        name_builder.append_entry_by_text("L", &cert_details.locality)?;
        name_builder.append_entry_by_text("O", &cert_details.organization)?;
        name_builder.append_entry_by_text("OU", &cert_details.org_unit)?;
        name_builder.append_entry_by_text("CN", &cert_details.common_name)?;
        Ok(name_builder.build())
    }
}

// ---- Store types --------------------------------------------------------

/// Public material persisted after a `GET /credentials` call.
/// Private keys are never stored, except the TLS CA key (needed to issue client certs).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum CredGenEntry {
    Tls {
        /// CA key/cert retained so `POST /client_creds` can issue a matching client cert.
        ca_key: Vec<u8>,
        ca_cert: Vec<u8>,
    },
    Symmetric {
        /// Shared key delivered to both server and client.
        key: Vec<u8>,
    },
    Ed25519 {
        /// Public key delivered to the owner via `POST /client_creds`.
        public_key: Vec<u8>,
    },
    Rsa {
        /// Public key delivered to the owner via `POST /client_creds`.
        public_key: Vec<u8>,
    },
    P256 {
        /// Self-signed cert delivered to the owner via `POST /client_creds`.
        cert_pem: Vec<u8>,
    },
    Random {
        /// Bytes delivered identically to both server and owner.
        bytes: Vec<u8>,
    },
}

/// TEE-side response (encrypted). Contains private key material.
#[derive(Debug, Serialize)]
pub struct ServerSecret {
    pub secret_name: String,
    pub secret_type: String,
    pub algorithm: String,
    #[serde(flatten)]
    pub material: ServerMaterial,
}

#[derive(Debug, Serialize)]
#[serde(tag = "material_type")]
pub enum ServerMaterial {
    Tls {
        private_key: Vec<u8>,
        cert: Vec<u8>,
        ca_cert: Vec<u8>,
    },
    Symmetric {
        key: Vec<u8>,
    },
    Ed25519 {
        private_key: Vec<u8>,
    },
    Rsa {
        private_key: Vec<u8>,
    },
    P256 {
        private_key: Vec<u8>,
    },
    Random {
        bytes: Vec<u8>,
    },
}

/// Owner-side response (plaintext). Contains only public material.
#[derive(Debug, Serialize)]
pub struct ClientSecret {
    pub secret_name: String,
    pub secret_type: String,
    pub algorithm: String,
    #[serde(flatten)]
    pub material: ClientMaterial,
}

#[derive(Debug, Serialize)]
#[serde(tag = "material_type")]
pub enum ClientMaterial {
    Tls {
        /// Freshly-issued client key and cert, plus the shared CA cert.
        private_key: Vec<u8>,
        cert: Vec<u8>,
        ca_cert: Vec<u8>,
    },
    Symmetric {
        /// Same bytes as delivered to the server.
        key: Vec<u8>,
    },
    Ed25519 {
        public_key: Vec<u8>,
    },
    Rsa {
        public_key: Vec<u8>,
    },
    P256 {
        cert_pem: Vec<u8>,
    },
    Random {
        /// Same bytes as delivered to the server.
        bytes: Vec<u8>,
    },
}

// ---- Plugin struct ------------------------------------------------------

/// Generates and delivers cryptographic credentials to attested TEEs and their workload owners.
pub struct CredGenPlugin {
    pub ca_config: TlsCertDetails,
    pub limits_config: SettingsConfig,

    /// KBS key-value store. Credential entries: `"{id_key}/{secret_name}.{type}.{algo}"`.
    /// Cert configs: `"{id_key}/__config.server"` / `"{id_key}/__config.client"`.
    store: KeyValueStorageInstance,
}

impl CredGenPlugin {
    pub async fn new(
        config: CredGenPluginConfig,
        storage_provider: Arc<dyn StorageProvider>,
    ) -> Result<Self> {
        let store = storage_provider
            .get_or_register("credgen")
            .await
            .context("credgen: failed to init storage backend")?;

        Ok(Self {
            ca_config: config.credgen.ca,
            limits_config: config.credgen.settings,
            store,
        })
    }
}

impl CredGenPlugin {
    // ---- Query helpers --------------------------------------------------

    /// Build the identity key from TEE-measured `init_data`.
    /// Uses attestation-bound data so query-string forgery cannot overwrite another guest's entry.
    /// Errors if `init_data` is absent or any [`IDENTITY_FIELDS`] field is missing/empty.
    fn identity_key_from_init_data(
        &self,
        init_data: Option<&serde_json::Value>,
    ) -> Result<String> {
        let claims = init_data
            .ok_or_else(|| anyhow!("init_data is required for credential generation"))?;

        let mut parts = Vec::with_capacity(IDENTITY_FIELDS.len());
        for key in IDENTITY_FIELDS {
            let val = claims
                .get(*key)
                .and_then(|v| v.as_str())
                .filter(|v| !v.trim().is_empty())
                .ok_or_else(|| anyhow!("init_data missing required field: '{}'", key))?;
            parts.push(val.to_string());
        }
        Ok(parts.join("_"))
    }

    /// Build the identity key from query params (owner-side requests; no init_data available).
    fn identity_key_from_query(&self, params: &HashMap<String, String>) -> String {
        IDENTITY_FIELDS
            .iter()
            .map(|k| params.get(*k).map(String::as_str).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("_")
    }

    /// Check that all [`IDENTITY_FIELDS`] are present and non-empty in the query string.
    fn validate_query(&self, query: &HashMap<String, String>) -> Result<()> {
        for key in IDENTITY_FIELDS {
            if !query.contains_key(*key) {
                bail!("Missing required query parameter: {}", key);
            }
            if query.get(*key).map(|v| v.trim().is_empty()).unwrap_or(true) {
                bail!("Query parameter '{}' cannot be empty", key);
            }
        }
        Ok(())
    }

    /// Parse `secret_name`, `secret_type`, and `algorithm` from the query string.
    /// Returns `(secret_name, SecretSpec, spec_sub_key)` where
    /// `spec_sub_key = "{secret_name}.{type}.{algorithm}"` (e.g. `"grpc.cert.tls"`).
    fn parse_spec_params(
        &self,
        query: &HashMap<String, String>,
    ) -> Result<(String, SecretSpec, String)> {
        let secret_name = query
            .get("secret_name")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| anyhow!("Missing or empty query parameter: secret_name"))?
            .clone();

        let type_str = query
            .get("secret_type")
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| anyhow!("Missing or empty query parameter: secret_type"))?;

        let secret_type = type_str
            .parse::<SecretType>()
            .map_err(|_| anyhow!("Unknown secret_type: '{}'. Valid values: cert, asymmetric, symmetric, random", type_str))?;

        // Optional; symmetric/random have defaults, cert/asymmetric require it.
        let algo_str = query
            .get("algorithm")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let spec = match secret_type {
            SecretType::Cert => {
                let a = algo_str
                    .ok_or_else(|| anyhow!("secret_type 'cert' requires an 'algorithm' parameter (tls, p256)"))?
                    .parse::<CertAlgorithm>()
                    .map_err(|_| anyhow!("Unknown algorithm for cert. Valid values: tls, p256"))?;
                SecretSpec::Cert(a)
            }
            SecretType::Asymmetric => {
                let a = algo_str
                    .ok_or_else(|| anyhow!("secret_type 'asymmetric' requires an 'algorithm' parameter (ed25519, rsa)"))?
                    .parse::<AsymmetricAlgorithm>()
                    .map_err(|_| anyhow!("Unknown algorithm for asymmetric. Valid values: ed25519, rsa"))?;
                SecretSpec::Asymmetric(a)
            }
            SecretType::Symmetric => {
                let a = algo_str
                    .unwrap_or_else(|| "raw".to_string())
                    .parse::<SymmetricAlgorithm>()
                    .map_err(|_| anyhow!("Unknown algorithm for symmetric. Valid values: raw"))?;
                SecretSpec::Symmetric(a)
            }
            SecretType::Random => {
                let a = algo_str
                    .unwrap_or_else(|| "csprng".to_string())
                    .parse::<RandomAlgorithm>()
                    .map_err(|_| anyhow!("Unknown algorithm for random. Valid values: csprng"))?;
                SecretSpec::Random(a)
            }
        };

        let allowlist_key = spec.allowlist_key();
        if !self.limits_config.supported_types.iter().any(|t| t == &allowlist_key) {
            bail!(
                "'{}' is not in supported_types {:?}",
                allowlist_key,
                self.limits_config.supported_types
            );
        }

        let spec_sub_key = format!("{}.{}.{}", secret_name, spec.type_str(), spec.algorithm_str());

        Ok((secret_name, spec, spec_sub_key))
    }

    // ---- Endpoint handlers ----------------------------------------------

    /// `GET /credentials` — generate credentials and return the private material to the TEE.
    /// Identity is taken from TEE-measured `init_data` to prevent query-string forgery.
    async fn build_server_response(
        &self,
        query: &HashMap<String, String>,
        init_data: Option<&serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let id_key = self.identity_key_from_init_data(init_data)?;
        let (secret_name, spec, spec_key) = self.parse_spec_params(query)?;

        let (entry, server_material) = match &spec {
            SecretSpec::Cert(CertAlgorithm::Tls) => {
                // New CA each call; stored so client certs chain to the same root.
                let ca = CredGenCA::new(&self.ca_config)?;

                let server_config = self.load_cert_config(&id_key, "server").await?;

                let (key, cert) = ca.generate_credentials(&server_config)?;

                let entry = CredGenEntry::Tls {
                    ca_key: ca.key.clone(),
                    ca_cert: ca.cert.clone(),
                };
                let material = ServerMaterial::Tls {
                    private_key: key.private_key_to_pem_pkcs8()?,
                    cert: cert.to_pem()?,
                    ca_cert: ca.cert,
                };
                (entry, material)
            }

            SecretSpec::Cert(CertAlgorithm::P256) => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                let ec_key = EcKey::generate(&group)?;
                let key = PKey::from_ec_key(ec_key)?;
                let private_key = key.private_key_to_pem_pkcs8()?;

                let cert_details = self.load_cert_config(&id_key, "server").await?;
                let cert = CredGenCA::generate_p256_self_signed_cert(&key, &cert_details)?;
                let cert_pem = cert.to_pem()?;

                // Store cert only; private key is not needed after delivery.
                let entry = CredGenEntry::P256 { cert_pem };
                let material = ServerMaterial::P256 { private_key };
                (entry, material)
            }

            SecretSpec::Asymmetric(AsymmetricAlgorithm::Ed25519) => {
                let key = PKey::generate_ed25519()?;
                let private_key = key.private_key_to_pem_pkcs8()?;
                let public_key = key.public_key_to_pem()?;

                // Store public key only; private key is not needed after delivery.
                let entry = CredGenEntry::Ed25519 { public_key };
                let material = ServerMaterial::Ed25519 { private_key };
                (entry, material)
            }

            SecretSpec::Asymmetric(AsymmetricAlgorithm::Rsa) => {
                let bits = self.limits_config.rsa_bits as u32;
                let rsa = Rsa::generate(bits)?;
                let key = PKey::from_rsa(rsa)?;
                let private_key = key.private_key_to_pem_pkcs8()?;
                let public_key = key.public_key_to_pem()?;

                // Store public key only; private key is not needed after delivery.
                let entry = CredGenEntry::Rsa { public_key };
                let material = ServerMaterial::Rsa { private_key };
                (entry, material)
            }

            SecretSpec::Symmetric(SymmetricAlgorithm::Raw) => {
                let size = self.limits_config.symmetric_key_size;
                let mut key = vec![0u8; size];
                openssl::rand::rand_bytes(&mut key)?;

                let entry = CredGenEntry::Symmetric { key: key.clone() };
                let material = ServerMaterial::Symmetric { key };
                (entry, material)
            }

            SecretSpec::Random(RandomAlgorithm::Csprng) => {
                let size = self.limits_config.random_bytes_size;
                let mut bytes = vec![0u8; size];
                openssl::rand::rand_bytes(&mut bytes)?;

                let entry = CredGenEntry::Random { bytes: bytes.clone() };
                let material = ServerMaterial::Random { bytes };
                (entry, material)
            }
        };

        let store_key = format!("{}/{}", id_key, spec_key);
        self.store
            .set(
                &store_key,
                &serde_json::to_vec(&entry)?,
                SetParameters { overwrite: true },
            )
            .await
            .context("credgen: failed to write entry to store")?;

        let response = ServerSecret {
            secret_name,
            secret_type: spec.type_str().to_string(),
            algorithm: spec.algorithm_str(),
            material: server_material,
        };
        Ok(serde_json::to_vec(&response)?)
    }

    /// `POST /client_creds` — return the public material for a previously generated secret.
    /// Identity comes from the query string (owner-side; no init_data). Requires admin auth.
    async fn build_client_response(&self, query: &HashMap<String, String>) -> Result<Vec<u8>> {
        self.validate_query(query)?;
        let id_key = self.identity_key_from_query(query);
        let (secret_name, spec, spec_key) = self.parse_spec_params(query)?;

        let client_config = self.load_cert_config(&id_key, "client").await?;

        let store_key = format!("{}/{}", id_key, spec_key);
        let raw = self
            .store
            .get(&store_key)
            .await
            .context("credgen: store read failed")?
            .ok_or_else(|| {
                anyhow!(
                    "No secret '{}' found for identity '{}'. \
                     The server must request credentials first.",
                    spec_key,
                    id_key
                )
            })?;
        let entry: CredGenEntry =
            serde_json::from_slice(&raw).context("credgen: failed to deserialize entry")?;

        let client_material: ClientMaterial = match &entry {
            CredGenEntry::Tls { ca_key, ca_cert } => {
                // Issue a fresh client cert from the CA stored by the last GET /credentials call.
                let ca = CredGenCA::init(ca_key.clone(), ca_cert.clone())?;
                let (key, cert) = ca.generate_credentials(&client_config)?;
                ClientMaterial::Tls {
                    private_key: key.private_key_to_pem_pkcs8()?,
                    cert: cert.to_pem()?,
                    ca_cert: ca.cert.clone(),
                }
            }
            CredGenEntry::Symmetric { key } => ClientMaterial::Symmetric { key: key.clone() },
            CredGenEntry::Ed25519 { public_key, .. } => {
                ClientMaterial::Ed25519 { public_key: public_key.clone() }
            }
            CredGenEntry::Rsa { public_key, .. } => {
                ClientMaterial::Rsa { public_key: public_key.clone() }
            }
            CredGenEntry::P256 { cert_pem, .. } => {
                ClientMaterial::P256 { cert_pem: cert_pem.clone() }
            }
            CredGenEntry::Random { bytes } => ClientMaterial::Random { bytes: bytes.clone() },
        };

        let response = ClientSecret {
            secret_name,
            secret_type: spec.type_str().to_string(),
            algorithm: spec.algorithm_str(),
            material: client_material,
        };
        Ok(serde_json::to_vec(&response)?)
    }

    /// `POST /list_pods` — return a JSON array of all identity keys in the store.
    async fn list_pods(&self) -> Result<Vec<u8>> {
        let all_keys = self.store.list().await.context("credgen: store list failed")?;
        // Keys are "{id_key}/…"; extract unique prefixes.
        let mut ids: Vec<String> = all_keys
            .into_iter()
            .filter_map(|k| k.split('/').next().map(str::to_string))
            .collect();
        ids.dedup();
        Ok(serde_json::to_vec(&ids)?)
    }

    /// Load cert config for `role` (`"server"` or `"client"`), falling back to defaults.
    async fn load_cert_config(&self, id_key: &str, role: &str) -> Result<TlsCertDetails> {
        let config_key = format!("{}/__config.{}", id_key, role);
        match self.store.get(&config_key).await.context("credgen: failed to read cert config")? {
            Some(raw) => serde_json::from_slice(&raw).context("credgen: failed to deserialize cert config"),
            None => {
                let mut d = TlsCertDetails::default();
                d.set_common_name(role);
                d.set_validity_days(DEFAULT_CERT_VALIDITY_DAYS);
                Ok(d)
            }
        }
    }

    /// `POST /update_cert` — persist custom cert subject fields for an identity.
    /// Body: JSON `{"server": <TlsCertDetails>, "client": <TlsCertDetails>}` (both optional).
    async fn update_cert_details(
        &self,
        query: &HashMap<String, String>,
        data: &[u8],
    ) -> Result<()> {
        self.validate_query(query)?;
        let id_key = self.identity_key_from_query(query);

        let wrapper: CertDetailsWrapper = serde_json::from_slice(data)
            .map_err(|e| anyhow!("Failed to deserialize JSON: {}", e))?;

        if let Some(updates) = wrapper.server {
            let config_key = format!("{}/__config.server", id_key);
            self.store
                .set(&config_key, &serde_json::to_vec(&updates)?, SetParameters { overwrite: true })
                .await
                .context("credgen: failed to write server cert config")?;
        }

        if let Some(updates) = wrapper.client {
            let config_key = format!("{}/__config.client", id_key);
            self.store
                .set(&config_key, &serde_json::to_vec(&updates)?, SetParameters { overwrite: true })
                .await
                .context("credgen: failed to write client cert config")?;
        }

        Ok(())
    }
}

// ---- ClientPlugin impl --------------------------------------------------

#[async_trait::async_trait]
impl ClientPlugin for CredGenPlugin {
    async fn handle(
        &self,
        body: &[u8],
        query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        init_data: Option<&serde_json::Value>,
    ) -> Result<Vec<u8>> {
        if path.len() != 1 {
            bail!("Illegal path. Only one path segment is supported");
        }

        match method.as_str() {
            "GET" => match path[0] {
                "credentials" => self.build_server_response(query, init_data).await,
                _ => Err(anyhow!("{} not supported", path[0])),
            },
            "POST" => match path[0] {
                "list_pods" => self.list_pods().await,
                "client_creds" => self.build_client_response(query).await,
                "update_cert" => {
                    self.update_cert_details(query, body).await?;
                    Ok(vec![])
                }
                _ => Err(anyhow!("{} not supported", path[0])),
            },
            _ => bail!("Illegal HTTP method. Only GET and POST are supported"),
        }
    }

    /// Require admin auth for POST requests; GET requests use attestation-based auth.
    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        Ok(method.as_str() != "GET")
    }

    /// Encrypt GET responses (TEE JWE envelope); POST responses carry only public material.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        method: &Method,
    ) -> Result<bool> {
        Ok(method.as_str() == "GET")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use key_value_storage::{KvStorageProvider, StorageBackendConfig, KeyValueStorageType, KeyValueStorageStructConfig};
    use serde_json::json;

    // ---- helpers --------------------------------------------------------

    fn memory_provider() -> Arc<KvStorageProvider> {
        KvStorageProvider::new(StorageBackendConfig {
            storage_type: KeyValueStorageType::Memory,
            backends: KeyValueStorageStructConfig::default(),
        })
    }

    async fn default_plugin() -> CredGenPlugin {
        CredGenPlugin::new(CredGenPluginConfig::default(), memory_provider())
            .await
            .expect("plugin init failed")
    }

    fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    fn identity_query(name: &str, ns: &str) -> HashMap<String, String> {
        query(&[("name", name), ("ns", ns)])
    }

    fn spec_query(name: &str, ns: &str, secret_name: &str, secret_type: &str, algorithm: Option<&str>) -> HashMap<String, String> {
        let mut q = identity_query(name, ns);
        q.insert("secret_name".into(), secret_name.into());
        q.insert("secret_type".into(), secret_type.into());
        if let Some(a) = algorithm {
            q.insert("algorithm".into(), a.into());
        }
        q
    }

    fn init_data(name: &str, ns: &str) -> serde_json::Value {
        json!({ "name": name, "ns": ns })
    }

    // ---- parse_spec_params ----------------------------------------------

    #[tokio::test]
    async fn parse_spec_cert_tls() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "grpc", "cert", Some("tls"));
        let (name, spec, key) = p.parse_spec_params(&q).unwrap();
        assert_eq!(name, "grpc");
        assert_eq!(spec.type_str(), "cert");
        assert_eq!(spec.algorithm_str(), "tls");
        assert_eq!(key, "grpc.cert.tls");
    }

    #[tokio::test]
    async fn parse_spec_cert_p256() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "mykey", "cert", Some("p256"));
        let (_, spec, key) = p.parse_spec_params(&q).unwrap();
        assert_eq!(spec.type_str(), "cert");
        assert_eq!(spec.algorithm_str(), "p256");
        assert_eq!(key, "mykey.cert.p256");
    }

    #[tokio::test]
    async fn parse_spec_asymmetric_ed25519() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "k", "asymmetric", Some("ed25519"));
        let (_, spec, key) = p.parse_spec_params(&q).unwrap();
        assert_eq!(spec.type_str(), "asymmetric");
        assert_eq!(spec.algorithm_str(), "ed25519");
        assert_eq!(key, "k.asymmetric.ed25519");
    }

    #[tokio::test]
    async fn parse_spec_asymmetric_rsa() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "k", "asymmetric", Some("rsa"));
        let (_, spec, _) = p.parse_spec_params(&q).unwrap();
        assert_eq!(spec.algorithm_str(), "rsa");
    }

    #[tokio::test]
    async fn parse_spec_symmetric_defaults_to_raw() {
        let p = default_plugin().await;
        // algorithm omitted — should default to "raw"
        let q = spec_query("pod", "default", "k", "symmetric", None);
        let (_, spec, key) = p.parse_spec_params(&q).unwrap();
        assert_eq!(spec.algorithm_str(), "raw");
        assert_eq!(key, "k.symmetric.raw");
    }

    #[tokio::test]
    async fn parse_spec_random_defaults_to_csprng() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "k", "random", None);
        let (_, spec, key) = p.parse_spec_params(&q).unwrap();
        assert_eq!(spec.algorithm_str(), "csprng");
        assert_eq!(key, "k.random.csprng");
    }

    #[tokio::test]
    async fn parse_spec_missing_secret_name_errors() {
        let p = default_plugin().await;
        let q = query(&[("name", "pod"), ("ns", "default"), ("secret_type", "cert"), ("algorithm", "tls")]);
        assert!(p.parse_spec_params(&q).is_err());
    }

    #[tokio::test]
    async fn parse_spec_unknown_type_errors() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "k", "unknown", Some("tls"));
        assert!(p.parse_spec_params(&q).is_err());
    }

    #[tokio::test]
    async fn parse_spec_cert_missing_algorithm_errors() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "k", "cert", None);
        assert!(p.parse_spec_params(&q).is_err());
    }

    #[tokio::test]
    async fn parse_spec_asymmetric_missing_algorithm_errors() {
        let p = default_plugin().await;
        let q = spec_query("pod", "default", "k", "asymmetric", None);
        assert!(p.parse_spec_params(&q).is_err());
    }

    #[tokio::test]
    async fn parse_spec_not_in_allowlist_errors() {
        let mut p = default_plugin().await;
        p.limits_config.supported_types = vec!["cert/tls".to_string()];
        let q = spec_query("pod", "default", "k", "asymmetric", Some("ed25519"));
        assert!(p.parse_spec_params(&q).is_err());
    }

    // ---- CredGenCA ------------------------------------------------------

    #[test]
    fn credgenca_new_produces_valid_pem() {
        let ca = CredGenCA::new(&TlsCertDetails::default()).unwrap();
        // Should parse back without error.
        openssl::pkey::PKey::private_key_from_pem(&ca.key).unwrap();
        openssl::x509::X509::from_pem(&ca.cert).unwrap();
    }

    #[test]
    fn credgenca_init_validates_pem() {
        let ca = CredGenCA::new(&TlsCertDetails::default()).unwrap();
        // Round-trip through init should succeed.
        CredGenCA::init(ca.key.clone(), ca.cert.clone()).unwrap();
        // Garbage bytes should fail.
        assert!(CredGenCA::init(b"not a key".to_vec(), ca.cert.clone()).is_err());
        assert!(CredGenCA::init(ca.key.clone(), b"not a cert".to_vec()).is_err());
    }

    #[test]
    fn credgenca_generate_credentials_issues_signed_cert() {
        let ca = CredGenCA::new(&TlsCertDetails::default()).unwrap();
        let mut details = TlsCertDetails::default();
        details.set_common_name("server");
        details.set_validity_days(90);
        let (key, cert) = ca.generate_credentials(&details).unwrap();
        // Key and cert should be parseable.
        assert!(!key.private_key_to_pem_pkcs8().unwrap().is_empty());
        assert!(!cert.to_pem().unwrap().is_empty());
    }

    #[test]
    fn credgenca_generate_p256_self_signed() {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let key = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let mut details = TlsCertDetails::default();
        details.set_common_name("test");
        let cert = CredGenCA::generate_p256_self_signed_cert(&key, &details).unwrap();
        assert!(!cert.to_pem().unwrap().is_empty());
    }

    // ---- build_server_response / build_client_response ------------------

    #[tokio::test]
    async fn cert_tls_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = spec_query("pod1", "default", "grpc", "cert", Some("tls"));

        // Server call generates and stores the TLS bundle.
        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["secret_type"], "cert");
        assert_eq!(server["algorithm"], "tls");
        assert_eq!(server["material_type"], "Tls");
        // Material fields are flattened to the top level.
        assert!(server["private_key"].is_array());
        assert!(server["cert"].is_array());
        assert!(server["ca_cert"].is_array());

        // Owner call returns a fresh client cert chained to the same CA.
        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["secret_type"], "cert");
        assert_eq!(client["algorithm"], "tls");
        assert_eq!(client["material_type"], "Tls");
        assert!(client["private_key"].is_array());
        assert!(client["cert"].is_array());
        // CA cert must be identical (same CA was used for both).
        assert_eq!(client["ca_cert"], server["ca_cert"]);
    }

    #[tokio::test]
    async fn cert_p256_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = spec_query("pod1", "default", "mycert", "cert", Some("p256"));

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["algorithm"], "p256");
        assert_eq!(server["material_type"], "P256");
        assert!(server["private_key"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["material_type"], "P256");
        assert!(client["cert_pem"].is_array());
    }

    #[tokio::test]
    async fn asymmetric_ed25519_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = spec_query("pod1", "default", "sigkey", "asymmetric", Some("ed25519"));

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["algorithm"], "ed25519");
        assert_eq!(server["material_type"], "Ed25519");
        assert!(server["private_key"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["material_type"], "Ed25519");
        assert!(client["public_key"].is_array());
    }

    #[tokio::test]
    async fn asymmetric_rsa_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = spec_query("pod1", "default", "rsakey", "asymmetric", Some("rsa"));

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["material_type"], "Rsa");
        assert!(server["private_key"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["material_type"], "Rsa");
        assert!(client["public_key"].is_array());
    }

    #[tokio::test]
    async fn symmetric_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = spec_query("pod1", "default", "aeskey", "symmetric", None);

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["material_type"], "Symmetric");
        assert!(server["key"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        // Server and client receive the same key bytes.
        assert_eq!(server["key"], client["key"]);
    }

    #[tokio::test]
    async fn random_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = spec_query("pod1", "default", "nonce", "random", None);

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["material_type"], "Random");
        assert!(server["bytes"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        // Server and client receive identical bytes.
        assert_eq!(server["bytes"], client["bytes"]);
    }

    #[tokio::test]
    async fn client_creds_before_server_errors() {
        let p = default_plugin().await;
        let q = spec_query("pod1", "default", "grpc", "cert", Some("tls"));
        assert!(p.build_client_response(&q).await.is_err());
    }

    #[tokio::test]
    async fn server_response_requires_init_data() {
        let p = default_plugin().await;
        let q = spec_query("pod1", "default", "grpc", "cert", Some("tls"));
        assert!(p.build_server_response(&q, None).await.is_err());
    }

    #[tokio::test]
    async fn identities_are_isolated() {
        let p = default_plugin().await;
        let q1 = spec_query("pod1", "default", "grpc", "cert", Some("tls"));
        let q2 = spec_query("pod2", "default", "grpc", "cert", Some("tls"));

        let id1 = init_data("pod1", "default");
        p.build_server_response(&q1, Some(&id1)).await.unwrap();

        // pod2 has not called GET /credentials yet — client_creds must fail.
        assert!(p.build_client_response(&q2).await.is_err());
    }

    // ---- update_cert_details / load_cert_config -------------------------

    #[tokio::test]
    async fn update_and_load_cert_config() {
        let p = default_plugin().await;
        let q = identity_query("pod1", "default");

        let body = serde_json::to_vec(&serde_json::json!({
            "server": { "common_name": "my-server", "validity_days": 30 },
            "client": { "common_name": "my-client", "validity_days": 15 }
        })).unwrap();

        p.update_cert_details(&q, &body).await.unwrap();

        let server_cfg = p.load_cert_config("pod1_default", "server").await.unwrap();
        assert_eq!(server_cfg.common_name, "my-server");
        assert_eq!(server_cfg.validity_days, 30);

        let client_cfg = p.load_cert_config("pod1_default", "client").await.unwrap();
        assert_eq!(client_cfg.common_name, "my-client");
        assert_eq!(client_cfg.validity_days, 15);
    }

    #[tokio::test]
    async fn load_cert_config_defaults_when_absent() {
        let p = default_plugin().await;
        let cfg = p.load_cert_config("pod1_default", "server").await.unwrap();
        assert_eq!(cfg.common_name, "server");
        assert_eq!(cfg.validity_days, DEFAULT_CERT_VALIDITY_DAYS);
    }

    #[tokio::test]
    async fn cert_config_applied_to_server_cert() {
        let p = default_plugin().await;
        let q = identity_query("pod1", "default");

        let body = serde_json::to_vec(&serde_json::json!({
            "server": { "common_name": "custom-cn" }
        })).unwrap();
        p.update_cert_details(&q, &body).await.unwrap();

        let id = init_data("pod1", "default");
        let sq = spec_query("pod1", "default", "grpc", "cert", Some("tls"));
        let server_bytes = p.build_server_response(&sq, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();

        // cert field is a Vec<u8>; parse it and verify the CN was applied.
        let cert_der = server["cert"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect::<Vec<u8>>();
        let cert = openssl::x509::X509::from_pem(&cert_der).unwrap();
        let cn = cert.subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap();
        assert_eq!(cn, "custom-cn");
    }

    // ---- list_pods ------------------------------------------------------

    #[tokio::test]
    async fn list_pods_returns_registered_identities() {
        let p = default_plugin().await;

        let id1 = init_data("pod1", "default");
        let id2 = init_data("pod2", "prod");
        p.build_server_response(&spec_query("pod1", "default", "g", "cert", Some("tls")), Some(&id1)).await.unwrap();
        p.build_server_response(&spec_query("pod2", "prod", "g", "cert", Some("tls")), Some(&id2)).await.unwrap();

        let list_bytes = p.list_pods().await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&list_bytes).unwrap();
        assert!(ids.contains(&"pod1_default".to_string()));
        assert!(ids.contains(&"pod2_prod".to_string()));
    }

    #[tokio::test]
    async fn list_pods_empty_store() {
        let p = default_plugin().await;
        let list_bytes = p.list_pods().await.unwrap();
        let ids: Vec<String> = serde_json::from_slice(&list_bytes).unwrap();
        assert!(ids.is_empty());
    }
}
