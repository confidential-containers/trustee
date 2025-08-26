use log::{debug, warn};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use async_trait::async_trait;
use base64::Engine;
use serde_json::{json, Value};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use openssl::x509::X509;

#[derive(Serialize, Deserialize, Debug)]
struct NvtrustTeeEvidence {
    /// The JWT token from NVTrust GPU attestation
    nvtrust_token: String,

    /// The nonce used in attestation
    #[serde(default = "String::default")]
    nonce: String,

    /// Report data included in the evidence
    #[serde(default = "String::default")]
    report_data: String,
}

/// Configuration for NVTrust JWT verification
#[derive(Debug)]
pub struct NvtrustConfig {
    /// Path to NVIDIA root certificates for JWT verification
    pub nvidia_cert_path: Option<String>,
    /// Whether to skip signature verification (for testing only)
    pub skip_signature_verification: bool,
}

impl Default for NvtrustConfig {
    fn default() -> Self {
        Self {
            nvidia_cert_path: Some("/Users/queenie.sun/Documents/GitHub/h3-pov/nvidia-certs/verifier_device_root.pem".to_string()),
            skip_signature_verification: false, // Enable real verification by default
        }
    }
}

#[derive(Debug)]
pub struct NvtrustVerifier {
    config: NvtrustConfig,
}

impl Default for NvtrustVerifier {
    fn default() -> Self {
        Self {
            config: NvtrustConfig::default(),
        }
    }
}

impl NvtrustVerifier {
    pub fn new(config: NvtrustConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Verifier for NvtrustVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tee_evidence = serde_json::from_value::<NvtrustTeeEvidence>(evidence)
            .context("Deserialize NVTrust Evidence failed.")?;

        verify_tee_evidence(&self.config, expected_report_data, expected_init_data_hash, &tee_evidence)
            .await
            .context("NVTrust Evidence verification error.")?;

        debug!("TEE-Evidence<nvtrust>: {:?}", tee_evidence);

        let claims = parse_tee_evidence(&tee_evidence)?;
        Ok((claims, "gpu".to_string()))
    }
}

async fn verify_tee_evidence(
    config: &NvtrustConfig,
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: &NvtrustTeeEvidence,
) -> Result<()> {
    if evidence.nvtrust_token.is_empty() {
        bail!("NVTrust token is empty");
    }

    // Parse JWT header to verify it's from NVIDIA
    let header = decode_header(&evidence.nvtrust_token)
        .context("Failed to decode JWT header")?;
    
    debug!("JWT header: {:?}", header);

    // Verify JWT token signature 
    let jwt_claims = if config.skip_signature_verification {
        warn!("⚠️  NVTrust JWT signature verification is DISABLED (testing mode)");
        warn!("⚠️  In production, enable signature verification with NVIDIA certificates");
        extract_jwt_payload_unsafe(&evidence.nvtrust_token)
            .context("Failed to extract JWT payload without verification")?
    } else {
        verify_jwt_signature_with_certs(config, &evidence.nvtrust_token)
            .context("JWT signature verification failed")?
    };

    // Verify nonce binding if provided
    if !evidence.nonce.is_empty() {
        verify_nonce_binding(&jwt_claims, &evidence.nonce)
            .context("Nonce binding verification failed")?;
    }

    // Verify the binding of report data
    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let ev_report_data = base64::engine::general_purpose::STANDARD
            .decode(&evidence.report_data)
            .context("base64 decode report data for NVTrust evidence")?;
        if *expected_report_data != ev_report_data {
            bail!("REPORT_DATA is different from that in NVTrust Evidence");
        }
    }

    if let InitDataHash::Value(_) = expected_init_data_hash {
        warn!("NVTrust does not support init data hash mechanism. skip.");
    }

    debug!("✅ NVTrust evidence verification completed");
    Ok(())
}

fn verify_jwt_signature_with_certs(config: &NvtrustConfig, token: &str) -> Result<Value> {
    if let Some(cert_path) = &config.nvidia_cert_path {
        debug!("Loading NVIDIA certificates from: {}", cert_path);
        
        // Load NVIDIA root certificate
        let cert_data = std::fs::read(cert_path)
            .with_context(|| format!("Failed to read NVIDIA certificate from {}", cert_path))?;
        
        let cert = X509::from_pem(&cert_data)
            .context("Failed to parse NVIDIA certificate as PEM")?;
        
        debug!("Loaded NVIDIA certificate: {}", 
               cert.subject_name().entries().next()
                   .map(|e| e.data().as_utf8().map(|s| s.to_string()).unwrap_or_else(|_| "unknown".to_string()))
                   .unwrap_or_else(|| "unknown".to_string()));

        // Extract public key from certificate
        let public_key = cert.public_key()
            .context("Failed to extract public key from NVIDIA certificate")?;
        
        // Convert OpenSSL public key to the format expected by jsonwebtoken
        let key_pem = public_key.public_key_to_pem()
            .context("Failed to convert public key to PEM")?;
        
        let decoding_key = DecodingKey::from_ec_pem(&key_pem)
            .context("Failed to create decoding key from NVIDIA certificate")?;
        
        // Set up JWT validation parameters
        let mut validation = Validation::new(Algorithm::ES256);
        validation.validate_exp = true; // Verify token expiration
        validation.validate_aud = false; // Skip audience validation for now
        
        // Decode and verify the JWT
        let token_data = decode::<Value>(token, &decoding_key, &validation)
            .context("JWT signature verification failed against NVIDIA certificate")?;
        
        debug!("✅ JWT signature successfully verified against NVIDIA certificate");
        debug!("✅ Token expires at: {:?}", token_data.claims.get("exp"));
        
        Ok(token_data.claims)
    } else {
        bail!("NVIDIA certificate path not configured but signature verification is enabled");
    }
}

fn verify_nonce_binding(jwt_claims: &Value, expected_nonce: &str) -> Result<()> {
    // Look for nonce in various possible JWT claim locations
    let jwt_nonce = jwt_claims.get("nonce")
        .or_else(|| jwt_claims.get("challenge"))
        .or_else(|| jwt_claims.get("user_data"))
        .and_then(|v| v.as_str());
    
    if let Some(jwt_nonce) = jwt_nonce {
        if jwt_nonce != expected_nonce {
            bail!("Nonce mismatch: expected '{}', found '{}' in JWT", expected_nonce, jwt_nonce);
        }
        debug!("✅ Nonce binding verified: {}", expected_nonce);
    } else {
        warn!("⚠️  No nonce found in JWT claims - cannot verify binding");
    }
    
    Ok(())
}

fn extract_jwt_payload_unsafe(token: &str) -> Result<Value> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        bail!("Invalid JWT format - expected 3 parts, found {}", parts.len());
    }
    
    let payload_b64 = parts[1];
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .context("Failed to decode JWT payload from base64")?;
    
    let payload: Value = serde_json::from_slice(&payload_bytes)
        .context("Failed to parse JWT payload as JSON")?;
    
    debug!("🔍 JWT payload extracted: {}", 
           serde_json::to_string_pretty(&payload).unwrap_or_default());
    
    Ok(payload)
}

// Parse the NVTrust evidence and extract claims
fn parse_tee_evidence(evidence: &NvtrustTeeEvidence) -> Result<TeeEvidenceParsedClaim> {
    // Extract claims from the JWT token
    let jwt_claims = extract_jwt_payload_unsafe(&evidence.nvtrust_token)
        .context("Failed to extract JWT claims")?;
    
    // Extract GPU-specific claims from the JWT - these are the REAL claims from NVIDIA
    let gpu_model = jwt_claims.get("gpu_model")
        .or_else(|| jwt_claims.get("device_name"))
        .or_else(|| jwt_claims.get("gpu_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    let driver_version = jwt_claims.get("driver_version")
        .or_else(|| jwt_claims.get("cuda_driver_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    let vbios_version = jwt_claims.get("vbios_version")
        .or_else(|| jwt_claims.get("gpu_vbios"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    
    let security_version = jwt_claims.get("security_version")
        .or_else(|| jwt_claims.get("tcb_version"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    // Hardware attestation claims
    let gpu_uuid = jwt_claims.get("gpu_uuid")
        .or_else(|| jwt_claims.get("device_uuid"))
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let attestation_time = jwt_claims.get("iat")
        .or_else(|| jwt_claims.get("timestamp"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    let claims_map = json!({
        // Original evidence data
        "nvtrust_token": evidence.nvtrust_token,
        "nonce": evidence.nonce,
        "report_data": evidence.report_data,
        
        // Real GPU-specific claims extracted from NVIDIA JWT
        "gpu_model": gpu_model,
        "gpu_driver_version": driver_version,
        "gpu_vbios_version": vbios_version,
        "security_version": security_version,
        "gpu_uuid": gpu_uuid,
        "attestation_timestamp": attestation_time,
        
        // Include the full JWT claims for inspection/debugging
        "jwt_claims": jwt_claims,
        
        // TEE metadata
        "tee_type": "nvtrust",
        "attestation_type": "gpu_hardware",
        "verifier_version": "0.1.0",
    });

    debug!("🔍 Extracted {} GPU claims from NVTrust JWT", 
           claims_map.as_object().map(|o| o.len()).unwrap_or(0));

    Ok(claims_map as TeeEvidenceParsedClaim)
}
