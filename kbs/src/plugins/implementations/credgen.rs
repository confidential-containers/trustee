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

pub const DEFAULT_CA_VALIDITY_DAYS: u32 = 365;
pub const DEFAULT_CERT_VALIDITY_DAYS: u32 = 90;
/// Default symmetric key size in bytes when `size` param is omitted.
pub const DEFAULT_SYMMETRIC_KEY_SIZE: usize = 32;

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
    /// Maximum symmetric key length in bytes. Per-request `size` must be in `1..=this`.
    pub symmetric_key_size_max: usize,
    /// RSA key size in bits.
    pub rsa_bits: usize,
    /// Allowed secret specs, `/`-joined: `"cert/{kind}/{algorithm}"` (e.g. `"cert/leaf_cert/ec_ed25519"`),
    /// `"asymmetric/{algorithm}"` (e.g. `"asymmetric/rsa"`), and plain `"symmetric"`.
    pub supported_types: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Default)]
pub struct CredGenConfig {
    #[serde(default)]
    pub ca: TlsCertDetails,

    #[serde(default)]
    pub settings: SettingsConfig,
}

/// How a certificate is issued (`kind` param for `secret_type=cert`).
/// Orthogonal to the key algorithm; `supported_types` selects which combinations are enabled.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum CertKind {
    /// A leaf certificate signed by a per-secret CA; delivered together with the CA cert.
    LeafCert,
    /// A self-signed CA certificate; no issuing CA is delivered alongside it.
    SelfSignedCa,
}

/// Key algorithm (`algorithm` param for `secret_type=cert` and `secret_type=asymmetric`).
/// `EcEd25519` and `EcP256` carry an `Ec` prefix to distinguish elliptic-curve algorithms
/// from the RSA category.
#[derive(Clone, Debug, Deserialize, Display, EnumString, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum KeyAlgorithm {
    EcEd25519,
    Rsa,
    EcP256,
}

impl KeyAlgorithm {
    /// Generate a fresh private key. `rsa_bits` is only used for RSA.
    fn generate(&self, rsa_bits: u32) -> Result<PKey<Private>> {
        Ok(match self {
            KeyAlgorithm::EcEd25519 => PKey::generate_ed25519()?,
            KeyAlgorithm::Rsa => PKey::from_rsa(Rsa::generate(rsa_bits)?)?,
            KeyAlgorithm::EcP256 => {
                let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
                PKey::from_ec_key(EcKey::generate(&group)?)?
            }
        })
    }
}

/// Fully-resolved secret specification parsed from the query string.
#[derive(Clone, Debug)]
pub enum SecretSpec {
    /// Algorithm is implied by the kind: `LeafCert` → EcEd25519, `SelfSignedCa` → EcP256.
    Cert(CertKind),
    Asymmetric(KeyAlgorithm),
    Symmetric(usize),
}

impl SecretSpec {
    /// `secret_type` string used in HTTP responses and store keys.
    pub fn type_str(&self) -> &'static str {
        match self {
            SecretSpec::Cert(..) => "cert",
            SecretSpec::Asymmetric(_) => "asymmetric",
            SecretSpec::Symmetric(_) => "symmetric",
        }
    }

    /// Certificate kind, if this is a cert.
    pub fn kind_str(&self) -> Option<String> {
        match self {
            SecretSpec::Cert(k) => Some(k.to_string()),
            _ => None,
        }
    }

    /// Key algorithm: implied by kind for certs, explicit for asymmetric keys.
    pub fn algorithm_str(&self) -> Option<String> {
        match self {
            SecretSpec::Cert(CertKind::LeafCert) => Some(KeyAlgorithm::EcEd25519.to_string()),
            SecretSpec::Cert(CertKind::SelfSignedCa) => Some(KeyAlgorithm::EcP256.to_string()),
            SecretSpec::Asymmetric(a) => Some(a.to_string()),
            SecretSpec::Symmetric(_) => None,
        }
    }

    /// `[type, kind?, algorithm?]` path components, used for the store key and the allowlist.
    fn parts(&self) -> Vec<String> {
        std::iter::once(self.type_str().to_string())
            .chain(self.kind_str())
            .chain(self.algorithm_str())
            .collect()
    }

    /// Key for the `supported_types` allowlist, e.g. `"cert/leaf_cert/ec_ed25519"`.
    pub fn allowlist_key(&self) -> String {
        self.parts().join("/")
    }

    /// Store sub-key for a secret of this spec, e.g. `"grpc.cert.leaf_cert.ec_ed25519"`.
    pub fn store_sub_key(&self, secret_name: &str) -> String {
        format!("{}.{}", secret_name, self.parts().join("."))
    }
}

#[derive(Deserialize)]
struct CertDetailsWrapper {
    client: Option<TlsCertDetails>,
    server: Option<TlsCertDetails>,
}

#[derive(Deserialize)]
struct SpecParams {
    secret_name: String,
    #[serde(flatten)]
    body: SpecBody,
}

#[derive(Deserialize)]
#[serde(tag = "secret_type", rename_all = "lowercase")]
enum SpecBody {
    Cert { kind: CertKind },
    Asymmetric { algorithm: KeyAlgorithm },
    Symmetric { size: Option<String> },
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

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            symmetric_key_size_max: 128,
            rsa_bits: 2048,
            supported_types: vec![
                "cert/leaf_cert/ec_ed25519".to_string(),
                "cert/self_signed_ca/ec_p256".to_string(),
                "asymmetric/ec_ed25519".to_string(),
                "asymmetric/rsa".to_string(),
                "symmetric".to_string(),
            ],
        }
    }
}

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

    /// Issue a fresh EcEd25519 end-entity key and certificate signed by this CA.
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
    fn generate_ca_cert(
        ca_private_key: &PKey<Private>,
        cert_details: &TlsCertDetails,
    ) -> Result<X509> {
        let name = Self::build_x509_name(cert_details)?;
        let mut b =
            Self::init_x509_builder(&name, &name, ca_private_key, cert_details.validity_days)?;
        b.sign(ca_private_key, MessageDigest::null())?;
        Ok(b.build())
    }

    /// Build a self-signed ECDSA (P-256) certificate. Uses SHA-256 digest (unlike EcEd25519).
    pub fn generate_self_signed_cert(
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

/// Material persisted after `GET /credentials`. The CA key for `LeafCert` is retained
/// so `POST /client_creds` can issue a matching client cert.
#[derive(Debug, Serialize, Deserialize)]
pub enum CredGenEntry {
    Cert(CertEntry),
    Asymmetric { public_key: Vec<u8> },
    Symmetric { key: Vec<u8> },
}

#[derive(Debug, Serialize, Deserialize)]
pub enum CertEntry {
    LeafCert { ca_key: Vec<u8>, ca_cert: Vec<u8> },
    SelfSignedCa { cert_pem: Vec<u8> },
}

/// Encrypted response to the TEE. Contains private key material.
#[derive(Debug, Serialize)]
pub struct ServerSecret {
    pub secret_name: String,
    pub secret_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(flatten)]
    pub material: ServerMaterial,
}

#[derive(Debug, Serialize)]
#[serde(tag = "material_type")]
pub enum ServerMaterial {
    Cert {
        private_key: Vec<u8>,
        cert: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        ca_cert: Option<Vec<u8>>, // present for LeafCert only
    },
    Asymmetric {
        private_key: Vec<u8>,
    },
    Symmetric {
        key: Vec<u8>,
    },
}

/// Plaintext response to the workload owner. Contains only public material.
#[derive(Debug, Serialize)]
pub struct ClientSecret {
    pub secret_name: String,
    pub secret_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(flatten)]
    pub material: ClientMaterial,
}

#[derive(Debug, Serialize)]
#[serde(tag = "material_type")]
pub enum ClientMaterial {
    Cert {
        cert: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        private_key: Option<Vec<u8>>, // LeafCert only
        #[serde(skip_serializing_if = "Option::is_none")]
        ca_cert: Option<Vec<u8>>, // LeafCert only
    },
    Asymmetric {
        public_key: Vec<u8>,
    },
    Symmetric {
        key: Vec<u8>,
    },
}

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
    /// Build the identity key from TEE-measured `init_data` (forgery-resistant).
    fn identity_key_from_init_data(&self, init_data: Option<&serde_json::Value>) -> Result<String> {
        let claims =
            init_data.ok_or_else(|| anyhow!("init_data is required for credential generation"))?;

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

    fn identity_key_from_query(&self, params: &HashMap<String, String>) -> String {
        IDENTITY_FIELDS
            .iter()
            .map(|k| params.get(*k).map(String::as_str).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("_")
    }

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

    /// Parse and validate `secret_name`, `secret_type`, and type-specific sub-params.
    /// Returns `(secret_name, SecretSpec, spec_sub_key)` where `spec_sub_key` is
    /// `"{secret_name}.{type}[.{kind}][.{algorithm}]"` (e.g. `"grpc.cert.leaf_cert.ec_ed25519"`).
    fn parse_spec_params(
        &self,
        query: &HashMap<String, String>,
    ) -> Result<(String, SecretSpec, String)> {
        let params: SpecParams = serde_json::from_value(serde_json::to_value(query)?)
            .context("invalid credential query params")?;

        if params.secret_name.trim().is_empty() {
            bail!("Missing or empty query parameter: secret_name");
        }

        let spec = match params.body {
            SpecBody::Cert { kind } => SecretSpec::Cert(kind),
            SpecBody::Asymmetric { algorithm } => SecretSpec::Asymmetric(algorithm),
            SpecBody::Symmetric { size } => {
                let n = match size {
                    Some(s) => s
                        .parse::<usize>()
                        .map_err(|_| anyhow!("'size' must be a positive integer, got '{s}'"))?,
                    None => DEFAULT_SYMMETRIC_KEY_SIZE,
                };
                if n == 0 {
                    bail!("'size' must be at least 1");
                }
                if n > self.limits_config.symmetric_key_size_max {
                    bail!(
                        "'size' {} exceeds maximum {}",
                        n,
                        self.limits_config.symmetric_key_size_max
                    );
                }
                SecretSpec::Symmetric(n)
            }
        };

        let allowlist_key = spec.allowlist_key();
        if !self
            .limits_config
            .supported_types
            .iter()
            .any(|t| t == &allowlist_key)
        {
            bail!(
                "'{}' is not in supported_types {:?}",
                allowlist_key,
                self.limits_config.supported_types
            );
        }

        let spec_sub_key = spec.store_sub_key(&params.secret_name);
        Ok((params.secret_name, spec, spec_sub_key))
    }

    /// Generate the [`CredGenEntry`] to persist and the [`ServerMaterial`] to return to the TEE.
    async fn generate_server_material(
        &self,
        spec: &SecretSpec,
        id_key: &str,
    ) -> Result<(CredGenEntry, ServerMaterial)> {
        match spec {
            SecretSpec::Cert(CertKind::LeafCert) => {
                let ca = CredGenCA::new(&self.ca_config)?;
                let server_config = self.load_cert_config(id_key, "server").await?;
                let (key, cert) = ca.generate_credentials(&server_config)?;
                let entry = CredGenEntry::Cert(CertEntry::LeafCert {
                    ca_key: ca.key.clone(),
                    ca_cert: ca.cert.clone(),
                });
                let material = ServerMaterial::Cert {
                    private_key: key.private_key_to_pem_pkcs8()?,
                    cert: cert.to_pem()?,
                    ca_cert: Some(ca.cert),
                };
                Ok((entry, material))
            }

            SecretSpec::Cert(CertKind::SelfSignedCa) => {
                let key = KeyAlgorithm::EcP256.generate(self.limits_config.rsa_bits as u32)?;
                let cert_details = self.load_cert_config(id_key, "server").await?;
                let cert_pem =
                    CredGenCA::generate_self_signed_cert(&key, &cert_details)?.to_pem()?;
                let entry = CredGenEntry::Cert(CertEntry::SelfSignedCa {
                    cert_pem: cert_pem.clone(),
                });
                let material = ServerMaterial::Cert {
                    private_key: key.private_key_to_pem_pkcs8()?,
                    cert: cert_pem,
                    ca_cert: None,
                };
                Ok((entry, material))
            }

            SecretSpec::Asymmetric(algorithm) => {
                let key = algorithm.generate(self.limits_config.rsa_bits as u32)?;
                let entry = CredGenEntry::Asymmetric {
                    public_key: key.public_key_to_pem()?,
                };
                let material = ServerMaterial::Asymmetric {
                    private_key: key.private_key_to_pem_pkcs8()?,
                };
                Ok((entry, material))
            }

            SecretSpec::Symmetric(size) => {
                let mut key = vec![0u8; *size];
                openssl::rand::rand_bytes(&mut key)?;
                let entry = CredGenEntry::Symmetric { key: key.clone() };
                let material = ServerMaterial::Symmetric { key };
                Ok((entry, material))
            }
        }
    }

    /// `GET /credentials` — generate credentials and return the private material to the TEE.
    /// Identity is taken from TEE-measured `init_data` to prevent query-string forgery.
    async fn build_server_response(
        &self,
        query: &HashMap<String, String>,
        init_data: Option<&serde_json::Value>,
    ) -> Result<Vec<u8>> {
        let id_key = self.identity_key_from_init_data(init_data)?;
        let (secret_name, spec, spec_key) = self.parse_spec_params(query)?;
        let (entry, material) = self.generate_server_material(&spec, &id_key).await?;

        self.store
            .set(
                &format!("{}/{}", id_key, spec_key),
                &serde_json::to_vec(&entry)?,
                SetParameters { overwrite: true },
            )
            .await
            .context("credgen: failed to write entry to store")?;

        Ok(serde_json::to_vec(&ServerSecret {
            secret_name,
            secret_type: spec.type_str().to_string(),
            kind: spec.kind_str(),
            algorithm: spec.algorithm_str(),
            material,
        })?)
    }

    /// Generate the [`ClientMaterial`] to return to the workload owner from a stored entry.
    async fn generate_client_material(
        &self,
        entry: &CredGenEntry,
        id_key: &str,
    ) -> Result<ClientMaterial> {
        let client_config = self.load_cert_config(id_key, "client").await?;
        match entry {
            CredGenEntry::Cert(CertEntry::LeafCert { ca_key, ca_cert }) => {
                let ca = CredGenCA::init(ca_key.clone(), ca_cert.clone())?;
                let (key, cert) = ca.generate_credentials(&client_config)?;
                Ok(ClientMaterial::Cert {
                    cert: cert.to_pem()?,
                    private_key: Some(key.private_key_to_pem_pkcs8()?),
                    ca_cert: Some(ca.cert.clone()),
                })
            }
            CredGenEntry::Cert(CertEntry::SelfSignedCa { cert_pem }) => Ok(ClientMaterial::Cert {
                cert: cert_pem.clone(),
                private_key: None,
                ca_cert: None,
            }),
            CredGenEntry::Asymmetric { public_key } => Ok(ClientMaterial::Asymmetric {
                public_key: public_key.clone(),
            }),
            CredGenEntry::Symmetric { key } => Ok(ClientMaterial::Symmetric { key: key.clone() }),
        }
    }

    /// `POST /client_creds` — return the public material for a previously generated secret.
    /// Identity comes from the query string (owner-side; no init_data). Requires admin auth.
    async fn build_client_response(&self, query: &HashMap<String, String>) -> Result<Vec<u8>> {
        self.validate_query(query)?;
        let id_key = self.identity_key_from_query(query);
        let (secret_name, spec, spec_key) = self.parse_spec_params(query)?;

        let raw = self
            .store
            .get(&format!("{}/{}", id_key, spec_key))
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
        let material = self.generate_client_material(&entry, &id_key).await?;

        Ok(serde_json::to_vec(&ClientSecret {
            secret_name,
            secret_type: spec.type_str().to_string(),
            kind: spec.kind_str(),
            algorithm: spec.algorithm_str(),
            material,
        })?)
    }

    /// `POST /list_pods` — return a JSON array of all identity keys in the store.
    async fn list_pods(&self) -> Result<Vec<u8>> {
        let all_keys = self
            .store
            .list()
            .await
            .context("credgen: store list failed")?;
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
        match self
            .store
            .get(&config_key)
            .await
            .context("credgen: failed to read cert config")?
        {
            Some(raw) => {
                serde_json::from_slice(&raw).context("credgen: failed to deserialize cert config")
            }
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
                .set(
                    &config_key,
                    &serde_json::to_vec(&updates)?,
                    SetParameters { overwrite: true },
                )
                .await
                .context("credgen: failed to write server cert config")?;
        }

        if let Some(updates) = wrapper.client {
            let config_key = format!("{}/__config.client", id_key);
            self.store
                .set(
                    &config_key,
                    &serde_json::to_vec(&updates)?,
                    SetParameters { overwrite: true },
                )
                .await
                .context("credgen: failed to write client cert config")?;
        }

        Ok(())
    }
}

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
    use key_value_storage::{
        KeyValueStorageStructConfig, KeyValueStorageType, KvStorageProvider, StorageBackendConfig,
    };
    use rstest::rstest;
    use serde_json::json;

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
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn identity_query(name: &str, ns: &str) -> HashMap<String, String> {
        query(&[("name", name), ("ns", ns)])
    }

    fn cert_query(
        name: &str,
        ns: &str,
        secret_name: &str,
        kind: &str,
        algorithm: &str,
    ) -> HashMap<String, String> {
        let mut q = identity_query(name, ns);
        q.insert("secret_name".into(), secret_name.into());
        q.insert("secret_type".into(), "cert".into());
        q.insert("kind".into(), kind.into());
        q.insert("algorithm".into(), algorithm.into());
        q
    }

    fn asym_query(
        name: &str,
        ns: &str,
        secret_name: &str,
        algorithm: &str,
    ) -> HashMap<String, String> {
        let mut q = identity_query(name, ns);
        q.insert("secret_name".into(), secret_name.into());
        q.insert("secret_type".into(), "asymmetric".into());
        q.insert("algorithm".into(), algorithm.into());
        q
    }

    fn sym_query(
        name: &str,
        ns: &str,
        secret_name: &str,
        size: Option<usize>,
    ) -> HashMap<String, String> {
        let mut q = identity_query(name, ns);
        q.insert("secret_name".into(), secret_name.into());
        q.insert("secret_type".into(), "symmetric".into());
        if let Some(s) = size {
            q.insert("size".into(), s.to_string());
        }
        q
    }

    fn init_data(name: &str, ns: &str) -> serde_json::Value {
        json!({ "name": name, "ns": ns })
    }

    #[rstest]
    #[case(
        cert_query("pod", "default", "grpc", "leaf_cert", "ec_ed25519"),
        "grpc",
        "cert",
        Some("leaf_cert"),
        Some("ec_ed25519"),
        "grpc.cert.leaf_cert.ec_ed25519"
    )]
    #[case(
        cert_query("pod", "default", "mykey", "self_signed_ca", "ec_p256"),
        "mykey",
        "cert",
        Some("self_signed_ca"),
        Some("ec_p256"),
        "mykey.cert.self_signed_ca.ec_p256"
    )]
    #[case(
        asym_query("pod", "default", "k", "ec_ed25519"),
        "k",
        "asymmetric",
        None,
        Some("ec_ed25519"),
        "k.asymmetric.ec_ed25519"
    )]
    #[case(
        asym_query("pod", "default", "k", "rsa"),
        "k",
        "asymmetric",
        None,
        Some("rsa"),
        "k.asymmetric.rsa"
    )]
    #[case(
        sym_query("pod", "default", "k", None),
        "k",
        "symmetric",
        None,
        None,
        "k.symmetric"
    )]
    #[case(
        {let mut q = sym_query("pod","default","k",None); q.insert("size".into(),"16".into()); q},
        "k", "symmetric", None, None, "k.symmetric"
    )]
    #[tokio::test]
    async fn parse_spec_ok(
        #[case] q: HashMap<String, String>,
        #[case] exp_name: &str,
        #[case] exp_type: &str,
        #[case] exp_kind: Option<&str>,
        #[case] exp_algo: Option<&str>,
        #[case] exp_key: &str,
    ) {
        let p = default_plugin().await;
        let (name, spec, key) = p.parse_spec_params(&q).unwrap();
        assert_eq!(name, exp_name);
        assert_eq!(spec.type_str(), exp_type);
        assert_eq!(spec.kind_str().as_deref(), exp_kind);
        assert_eq!(spec.algorithm_str().as_deref(), exp_algo);
        assert_eq!(key, exp_key);
    }

    #[tokio::test]
    async fn parse_spec_symmetric_size_values() {
        let p = default_plugin().await;
        let (_, spec, _) = p
            .parse_spec_params(&sym_query("pod", "default", "k", None))
            .unwrap();
        assert!(matches!(spec, SecretSpec::Symmetric(s) if s == DEFAULT_SYMMETRIC_KEY_SIZE));

        let mut q = sym_query("pod", "default", "k", None);
        q.insert("size".into(), "16".into());
        let (_, spec, _) = p.parse_spec_params(&q).unwrap();
        assert!(matches!(spec, SecretSpec::Symmetric(16)));
    }

    #[rstest]
    #[case(query(&[("name","pod"),("ns","default"),("secret_type","cert"),("kind","leaf_cert")]))]
    #[case(query(&[("name","pod"),("ns","default"),("secret_name","k"),("secret_type","unknown")]))]
    #[case({let mut q = identity_query("pod","default"); q.insert("secret_name".into(),"k".into()); q.insert("secret_type".into(),"cert".into()); q})]
    #[case({let mut q = identity_query("pod","default"); q.insert("secret_name".into(),"k".into()); q.insert("secret_type".into(),"asymmetric".into()); q})]
    #[case({let mut q = sym_query("pod","default","k",None); q.insert("size".into(),"0".into()); q})]
    #[case({let mut q = sym_query("pod","default","k",None); q.insert("size".into(),"999".into()); q})]
    #[case(asym_query("pod", "default", "k", "ec_ed25519"))]
    #[tokio::test]
    async fn parse_spec_errors(#[case] q: HashMap<String, String>) {
        let mut p = default_plugin().await;
        // allowlist restricted so the last case (asymmetric not in list) also fails
        p.limits_config.supported_types = vec!["cert/leaf_cert/ec_ed25519".to_string()];
        assert!(p.parse_spec_params(&q).is_err());
    }

    #[test]
    fn credgenca_smoke() {
        let ca = CredGenCA::new(&TlsCertDetails::default()).unwrap();
        openssl::pkey::PKey::private_key_from_pem(&ca.key).unwrap();
        openssl::x509::X509::from_pem(&ca.cert).unwrap();

        CredGenCA::init(ca.key.clone(), ca.cert.clone()).unwrap();
        assert!(CredGenCA::init(b"not a key".to_vec(), ca.cert.clone()).is_err());
        assert!(CredGenCA::init(ca.key.clone(), b"not a cert".to_vec()).is_err());

        let mut details = TlsCertDetails::default();
        details.set_common_name("server");
        details.set_validity_days(90);
        let (key, cert) = ca.generate_credentials(&details).unwrap();
        assert!(!key.private_key_to_pem_pkcs8().unwrap().is_empty());
        assert!(!cert.to_pem().unwrap().is_empty());

        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let p256_key = openssl::pkey::PKey::from_ec_key(ec_key).unwrap();
        let mut details = TlsCertDetails::default();
        details.set_common_name("test");
        assert!(!CredGenCA::generate_self_signed_cert(&p256_key, &details)
            .unwrap()
            .to_pem()
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn cert_tls_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = cert_query("pod1", "default", "grpc", "leaf_cert", "ec_ed25519");

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["secret_type"], "cert");
        assert_eq!(server["kind"], "leaf_cert");
        assert_eq!(server["algorithm"], "ec_ed25519");
        assert_eq!(server["material_type"], "Cert");
        assert!(server["private_key"].is_array());
        assert!(server["cert"].is_array());
        assert!(server["ca_cert"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["secret_type"], "cert");
        assert_eq!(client["kind"], "leaf_cert");
        assert_eq!(client["algorithm"], "ec_ed25519");
        assert_eq!(client["material_type"], "Cert");
        assert!(client["private_key"].is_array());
        assert!(client["cert"].is_array());
        assert_eq!(client["ca_cert"], server["ca_cert"]);
    }

    #[tokio::test]
    async fn cert_p256_roundtrip() {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");
        let q = cert_query("pod1", "default", "mycert", "self_signed_ca", "ec_p256");

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["kind"], "self_signed_ca");
        assert_eq!(server["algorithm"], "ec_p256");
        assert_eq!(server["material_type"], "Cert");
        assert!(server["private_key"].is_array());
        assert!(server["cert"].is_array());
        assert!(server.get("ca_cert").is_none());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["material_type"], "Cert");
        assert_eq!(client["cert"], server["cert"]);
        assert!(client.get("private_key").is_none());
        assert!(client.get("ca_cert").is_none());
    }

    #[rstest]
    #[case(asym_query("pod1", "default", "sigkey", "ec_ed25519"), "ec_ed25519")]
    #[case(asym_query("pod1", "default", "rsakey", "rsa"), "rsa")]
    #[tokio::test]
    async fn asymmetric_roundtrip(#[case] q: HashMap<String, String>, #[case] exp_algo: &str) {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["algorithm"], exp_algo);
        assert!(server.get("kind").is_none());
        assert_eq!(server["material_type"], "Asymmetric");
        assert!(server["private_key"].is_array());

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(client["material_type"], "Asymmetric");
        assert!(client["public_key"].is_array());
    }

    #[rstest]
    #[case(sym_query("pod1", "default", "aeskey", None), 32)]
    #[case(sym_query("pod1", "default", "aeskey16", Some(16)), 16)]
    #[tokio::test]
    async fn symmetric_roundtrip(#[case] q: HashMap<String, String>, #[case] exp_len: usize) {
        let p = default_plugin().await;
        let id = init_data("pod1", "default");

        let server_bytes = p.build_server_response(&q, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();
        assert_eq!(server["material_type"], "Symmetric");
        assert_eq!(server["key"].as_array().unwrap().len(), exp_len);

        let client_bytes = p.build_client_response(&q).await.unwrap();
        let client: serde_json::Value = serde_json::from_slice(&client_bytes).unwrap();
        assert_eq!(server["key"], client["key"]);
    }

    #[tokio::test]
    async fn client_creds_before_server_errors() {
        let p = default_plugin().await;
        let q = cert_query("pod1", "default", "grpc", "leaf_cert", "ec_ed25519");
        assert!(p.build_client_response(&q).await.is_err());
    }

    #[tokio::test]
    async fn server_response_requires_init_data() {
        let p = default_plugin().await;
        let q = cert_query("pod1", "default", "grpc", "leaf_cert", "ec_ed25519");
        assert!(p.build_server_response(&q, None).await.is_err());
    }

    #[tokio::test]
    async fn identities_are_isolated() {
        let p = default_plugin().await;
        let q1 = cert_query("pod1", "default", "grpc", "leaf_cert", "ec_ed25519");
        let q2 = cert_query("pod2", "default", "grpc", "leaf_cert", "ec_ed25519");

        let id1 = init_data("pod1", "default");
        p.build_server_response(&q1, Some(&id1)).await.unwrap();
        assert!(p.build_client_response(&q2).await.is_err());
    }

    #[tokio::test]
    async fn update_and_load_cert_config() {
        let p = default_plugin().await;
        let q = identity_query("pod1", "default");

        let body = serde_json::to_vec(&serde_json::json!({
            "server": { "common_name": "my-server", "validity_days": 30 },
            "client": { "common_name": "my-client", "validity_days": 15 }
        }))
        .unwrap();

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
        }))
        .unwrap();
        p.update_cert_details(&q, &body).await.unwrap();

        let id = init_data("pod1", "default");
        let sq = cert_query("pod1", "default", "grpc", "leaf_cert", "ec_ed25519");
        let server_bytes = p.build_server_response(&sq, Some(&id)).await.unwrap();
        let server: serde_json::Value = serde_json::from_slice(&server_bytes).unwrap();

        let cert_der = server["cert"]
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b.as_u64().unwrap() as u8)
            .collect::<Vec<u8>>();
        let cert = openssl::x509::X509::from_pem(&cert_der).unwrap();
        let cn = cert
            .subject_name()
            .entries_by_nid(openssl::nid::Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap();
        assert_eq!(cn, "custom-cn");
    }

    #[tokio::test]
    async fn list_pods_returns_registered_identities() {
        let p = default_plugin().await;

        let id1 = init_data("pod1", "default");
        let id2 = init_data("pod2", "prod");
        p.build_server_response(
            &cert_query("pod1", "default", "g", "leaf_cert", "ec_ed25519"),
            Some(&id1),
        )
        .await
        .unwrap();
        p.build_server_response(
            &cert_query("pod2", "prod", "g", "leaf_cert", "ec_ed25519"),
            Some(&id2),
        )
        .await
        .unwrap();

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
