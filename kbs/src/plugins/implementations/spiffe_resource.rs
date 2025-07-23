use actix_web::http::Method;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

// OpenSSL imports for certificate generation
use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName};
use openssl::x509::{X509NameBuilder, X509Req, X509ReqBuilder, X509, X509Builder};

use super::super::plugin_manager::ClientPlugin;

/// Attestation context for SPIFFE ID generation
#[derive(Debug, Clone)]
pub struct AttestationContext {
    pub workload_type: WorkloadType,
    pub workload_name: String,
    pub container_image: String,
    pub gpu_attestation: Option<GpuAttestationClaims>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum WorkloadType {
    GpuInference,
    GpuTraining,
    CpuWorkload,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct GpuAttestationClaims {
    pub gpu_model: String,
    pub attestation_valid: bool,
    pub secure_boot_enabled: bool,
    pub measurement_valid: bool,
}

impl AttestationContext {
    pub fn has_valid_gpu_attestation(&self) -> bool {
        self.gpu_attestation
            .as_ref()
            .map(|gpu| gpu.attestation_valid && gpu.secure_boot_enabled && gpu.measurement_valid)
            .unwrap_or(false)
    }

    /// Extract attestation context from KBS token claims (if available)
    /// This would integrate with real KBS attestation data in production
    pub fn from_kbs_claims(_claims: Option<&serde_json::Value>) -> Self {
        // TODO: Extract real attestation data from KBS claims
        // For now, return mock data for demonstration
        // In production, this would parse:
        // - claims["tcb-status"] for hardware attestation
        // - claims["customized_claims"]["init_data"] for workload configuration
        // - claims["customized_claims"]["runtime_data"] for runtime info
        // 
        // Production Implementation Plan:
        // 1. KBS passes attestation token claims to plugin via request context
        // 2. Parse claims to extract:
        //    - TEE type (TDX, SGX, etc.) from tcb-status
        //    - GPU attestation data from hardware evidence
        //    - Container image info from init_data
        //    - Workload type from runtime_data or policy evaluation
        // 3. Validate attestation signatures and measurement chains
        // 4. Generate workload-specific SPIFFE ID based on validated claims
        //
        // Example claim structure:
        // {
        //   "tcb-status": {
        //     "tdx.quote.body.mr_td": "...",
        //     "tdx.quote.body.rtmr0": "...",
        //     "gpu_attestation": { "model": "H100", "valid": true }
        //   },
        //   "customized_claims": {
        //     "init_data": { "container_image": "virtru/llama:v1.2" },
        //     "runtime_data": { "workload_type": "gpu-inference" }
        //   }
        // }
        Self::create_mock_gpu_workload()
    }

    /// Create mock GPU workload for testing/POC
    pub fn create_mock_gpu_workload() -> Self {
        AttestationContext {
            workload_type: WorkloadType::GpuInference,
            workload_name: "llama-inference".to_string(),
            container_image: "virtru/llama:v1.2".to_string(),
            gpu_attestation: Some(GpuAttestationClaims {
                gpu_model: "H100".to_string(),
                attestation_valid: true,
                secure_boot_enabled: true,
                measurement_valid: true,
            }),
        }
    }

    /// Create mock CPU workload for testing/POC
    pub fn create_mock_cpu_workload() -> Self {
        AttestationContext {
            workload_type: WorkloadType::CpuWorkload,
            workload_name: "data-processing".to_string(),
            container_image: "virtru/cpu-worker:v1.0".to_string(),
            gpu_attestation: None,
        }
    }
}

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SpiffeResourceConfig { 
    pub trust_domain: String,
    pub ca_cert_path: String,
    pub ca_key_path: String,
    pub cert_ttl_hours: Option<u64>, // Optional with default
}

pub struct SpiffeResourcePlugin {  
    trust_domain: String,
    ca_cert_path: String,
    ca_key_path: String,
    cert_ttl_hours: u64,
}

impl TryFrom<SpiffeResourceConfig> for SpiffeResourcePlugin {
    type Error = anyhow::Error;

    fn try_from(config: SpiffeResourceConfig) -> Result<Self> {
        Ok(Self {
            trust_domain: config.trust_domain,
            ca_cert_path: config.ca_cert_path,
            ca_key_path: config.ca_key_path,
            cert_ttl_hours: config.cert_ttl_hours.unwrap_or(24), // Default 24 hours
        })
    }
}

impl SpiffeResourcePlugin {
    /// Load the CA certificate from the configured path
    fn load_ca_cert(&self) -> Result<X509> {
        let ca_cert_data = fs::read(&self.ca_cert_path)
            .with_context(|| format!("Failed to read CA certificate from {}", self.ca_cert_path))?;
        
        let ca_cert = X509::from_pem(&ca_cert_data)
            .context("Failed to parse CA certificate PEM")?;
        
        Ok(ca_cert)
    }

    /// Load the CA private key from the configured path
    fn load_ca_key(&self) -> Result<PKey<Private>> {
        let ca_key_data = fs::read(&self.ca_key_path)
            .with_context(|| format!("Failed to read CA private key from {}", self.ca_key_path))?;
        
        let ca_key = PKey::private_key_from_pem(&ca_key_data)
            .context("Failed to parse CA private key PEM")?;
        
        Ok(ca_key)
    }

    /// Generate a SPIFFE ID based on attestation data
    fn generate_spiffe_id_from_attestation(&self, attestation: &AttestationContext) -> String {
        match &attestation.workload_type {
            WorkloadType::GpuInference if attestation.has_valid_gpu_attestation() => {
                format!("spiffe://{}/gpu/inference", self.trust_domain)
            }
            WorkloadType::GpuTraining if attestation.has_valid_gpu_attestation() => {
                format!("spiffe://{}/gpu/training", self.trust_domain)
            }
            WorkloadType::CpuWorkload => {
                format!("spiffe://{}/cpu/{}", self.trust_domain, attestation.workload_name)
            }
            _ => {
                format!("spiffe://{}/workload/default", self.trust_domain)
            }
        }
    }

    /// Generate a new RSA private key for the workload
    fn generate_workload_key() -> Result<PKey<Private>> {
        let rsa = Rsa::generate(2048)
            .context("Failed to generate RSA key pair")?;
        let pkey = PKey::from_rsa(rsa)
            .context("Failed to convert RSA to PKey")?;
        Ok(pkey)
    }

    /// Create a Certificate Signing Request (CSR) for the workload
    fn create_csr(&self, workload_key: &PKey<Private>, spiffe_id: &str) -> Result<X509Req> {
        let mut req_builder = X509ReqBuilder::new()
            .context("Failed to create CSR builder")?;

        // Set the public key
        req_builder.set_pubkey(workload_key)
            .context("Failed to set public key in CSR")?;

        // Create subject name (SPIFFE certificates typically have minimal subject info)
        let mut name_builder = X509NameBuilder::new()
            .context("Failed to create X509 name builder")?;
        name_builder.append_entry_by_text("CN", spiffe_id)
            .context("Failed to set CN in subject")?;
        let subject_name = name_builder.build();
        
        req_builder.set_subject_name(&subject_name)
            .context("Failed to set subject name")?;

        // Sign the CSR with the workload's private key
        req_builder.sign(workload_key, MessageDigest::sha256())
            .context("Failed to sign CSR")?;

        Ok(req_builder.build())
    }

    /// Issue a SPIFFE certificate for the given SPIFFE ID
    pub fn issue_spiffe_certificate(&self, spiffe_id: &str) -> Result<(X509, PKey<Private>)> {
        // Load CA certificate and key
        let ca_cert = self.load_ca_cert()?;
        let ca_key = self.load_ca_key()?;

        // Generate workload key pair
        let workload_key = Self::generate_workload_key()?;

        // Create CSR
        let csr = self.create_csr(&workload_key, spiffe_id)?;

        // Create certificate from CSR
        let mut cert_builder = X509Builder::new()
            .context("Failed to create certificate builder")?;

        // Set version to V3
        cert_builder.set_version(2)
            .context("Failed to set certificate version")?;

        // Generate serial number
        let mut serial = BigNum::new()
            .context("Failed to create BigNum for serial")?;
        serial.rand(128, MsbOption::MAYBE_ZERO, false)
            .context("Failed to generate random serial number")?;
        let serial_asn1 = serial.to_asn1_integer()
            .context("Failed to convert serial to ASN1")?;
        cert_builder.set_serial_number(&serial_asn1)
            .context("Failed to set serial number")?;

        // Set subject from CSR
        cert_builder.set_subject_name(csr.subject_name())
            .context("Failed to set subject name")?;

        // Set issuer to CA subject
        cert_builder.set_issuer_name(ca_cert.subject_name())
            .context("Failed to set issuer name")?;

        // Set public key from CSR
        cert_builder.set_pubkey(csr.public_key()?.as_ref())
            .context("Failed to set public key")?;

        // Set validity period
        let not_before = Asn1Time::days_from_now(0)
            .context("Failed to create not_before time")?;
        let not_after = Asn1Time::days_from_now(self.cert_ttl_hours as u32 / 24)
            .context("Failed to create not_after time")?;
        
        cert_builder.set_not_before(&not_before)
            .context("Failed to set not_before")?;
        cert_builder.set_not_after(&not_after)
            .context("Failed to set not_after")?;

        // Add SPIFFE ID as Subject Alternative Name (SAN) - This is critical!
        let san_extension = SubjectAlternativeName::new()
            .uri(spiffe_id)
            .build(&cert_builder.x509v3_context(Some(&ca_cert), None))
            .context("Failed to create SAN extension")?;
        cert_builder.append_extension(san_extension)
            .context("Failed to add SAN extension")?;

        // Add standard extensions for SPIFFE certificates
        let key_usage = KeyUsage::new()
            .digital_signature()
            .key_encipherment()
            .build()
            .context("Failed to create key usage extension")?;
        cert_builder.append_extension(key_usage)
            .context("Failed to add key usage extension")?;

        let extended_key_usage = ExtendedKeyUsage::new()
            .client_auth()
            .server_auth()
            .build()
            .context("Failed to create extended key usage extension")?;
        cert_builder.append_extension(extended_key_usage)
            .context("Failed to add extended key usage extension")?;

        // Sign the certificate with CA key
        cert_builder.sign(&ca_key, MessageDigest::sha256())
            .context("Failed to sign certificate")?;

        let certificate = cert_builder.build();

        Ok((certificate, workload_key))
    }
}

#[async_trait::async_trait]
impl ClientPlugin for SpiffeResourcePlugin {
    async fn handle(
        &self,
        _body: &[u8],
        _query: &str,
        path: &str,
        _method: &Method,
    ) -> Result<Vec<u8>> {
        // Extract workload identifier from path
        // Path format: /kbs/v0/spiffe-resource/<workload_id>
        let workload_id = if path.is_empty() || path == "/" {
            "default-workload"
        } else {
            path.trim_start_matches('/')
        };

        // TODO: In production, extract attestation context from KBS request context
        // For now, we'll use mock attestation data based on workload_id
        let attestation_context = if workload_id.contains("gpu") {
            AttestationContext::create_mock_gpu_workload()
        } else {
            AttestationContext::create_mock_cpu_workload()
        };

        // Generate SPIFFE ID based on attestation context (preferred method)
        let spiffe_id = self.generate_spiffe_id_from_attestation(&attestation_context);

        // Issue the certificate
        match self.issue_spiffe_certificate(&spiffe_id) {
            Ok((certificate, private_key)) => {
                // Convert certificate and key to PEM format
                let cert_pem = certificate.to_pem()
                    .context("Failed to convert certificate to PEM")?;
                let key_pem = private_key.private_key_to_pem_pkcs8()
                    .context("Failed to convert private key to PEM")?;

                // Create response containing both certificate and private key
                // In a real implementation, you might want to return these separately
                // or use a structured format like JSON
                let mut response = Vec::new();
                response.extend_from_slice(b"-----BEGIN CERTIFICATE BUNDLE-----\n");
                response.extend_from_slice(&cert_pem);
                response.extend_from_slice(b"\n-----BEGIN PRIVATE KEY-----\n");
                response.extend_from_slice(&key_pem);
                response.extend_from_slice(b"-----END CERTIFICATE BUNDLE-----\n");

                log::info!(
                    "Issued SPIFFE certificate for: {} (workload: {}, type: {:?})", 
                    spiffe_id, 
                    attestation_context.workload_name, 
                    attestation_context.workload_type
                );
                Ok(response)
            }
            Err(e) => {
                log::error!("Failed to issue SPIFFE certificate for {}: {}", spiffe_id, e);
                Err(e)
            }
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }
}

