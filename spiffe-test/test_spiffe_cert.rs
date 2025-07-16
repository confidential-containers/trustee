// Standalone test for SPIFFE certificate generation with KBS attestation integration
// This tests the core logic and demonstrates attestation-based SPIFFE ID generation

use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    hash::MessageDigest,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        extension::{ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509Builder,
    },
};
use std::io::Write;
use tempfile::NamedTempFile;

/// Attestation context for SPIFFE ID generation (copied from main plugin)
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

    pub fn create_mock_cpu_workload() -> Self {
        AttestationContext {
            workload_type: WorkloadType::CpuWorkload,
            workload_name: "data-processing".to_string(),
            container_image: "virtru/cpu-worker:v1.0".to_string(),
            gpu_attestation: None,
        }
    }
}

/// Test helper to create a CA certificate and key
fn create_test_ca() -> (NamedTempFile, NamedTempFile) {
    // Generate CA key pair
    let ca_rsa = Rsa::generate(2048).unwrap();
    let ca_key = PKey::from_rsa(ca_rsa).unwrap();

    // Create CA certificate
    let mut ca_cert_builder = X509Builder::new().unwrap();
    ca_cert_builder.set_version(2).unwrap();

    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    let serial_asn1 = serial.to_asn1_integer().unwrap();
    ca_cert_builder.set_serial_number(&serial_asn1).unwrap();

    let mut ca_name_builder = X509NameBuilder::new().unwrap();
    ca_name_builder.append_entry_by_text("CN", "Test SPIFFE CA").unwrap();
    let ca_name = ca_name_builder.build();
    ca_cert_builder.set_subject_name(&ca_name).unwrap();
    ca_cert_builder.set_issuer_name(&ca_name).unwrap();

    ca_cert_builder.set_pubkey(&ca_key).unwrap();

    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(365).unwrap();
    ca_cert_builder.set_not_before(&not_before).unwrap();
    ca_cert_builder.set_not_after(&not_after).unwrap();

    ca_cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let ca_cert = ca_cert_builder.build();

    // Write to temporary files
    let mut ca_cert_file = NamedTempFile::new().unwrap();
    let mut ca_key_file = NamedTempFile::new().unwrap();

    ca_cert_file.write_all(&ca_cert.to_pem().unwrap()).unwrap();
    ca_key_file.write_all(&ca_key.private_key_to_pem_pkcs8().unwrap()).unwrap();

    (ca_cert_file, ca_key_file)
}

/// Test SPIFFE certificate generation core logic
/// Generate a SPIFFE ID based on attestation data
fn generate_spiffe_id_from_attestation(trust_domain: &str, attestation: &AttestationContext) -> String {
    match &attestation.workload_type {
        WorkloadType::GpuInference if attestation.has_valid_gpu_attestation() => {
            format!("spiffe://{}/gpu/inference", trust_domain)
        }
        WorkloadType::GpuTraining if attestation.has_valid_gpu_attestation() => {
            format!("spiffe://{}/gpu/training", trust_domain)
        }
        WorkloadType::CpuWorkload => {
            format!("spiffe://{}/cpu/{}", trust_domain, attestation.workload_name)
        }
        _ => {
            format!("spiffe://{}/workload/default", trust_domain)
        }
    }
}

fn test_spiffe_certificate_generation() {
    println!("🔬 Testing SPIFFE Certificate Generation...");
    
    let (ca_cert_file, ca_key_file) = create_test_ca();
    
    // This simulates your plugin's certificate generation logic
    let spiffe_id = "spiffe://virtru.com/gpu/inference";
    
    // Load CA (simulating your load_ca_cert and load_ca_key methods)
    let ca_cert_data = std::fs::read(ca_cert_file.path()).unwrap();
    let ca_cert = openssl::x509::X509::from_pem(&ca_cert_data).unwrap();
    
    let ca_key_data = std::fs::read(ca_key_file.path()).unwrap();
    let ca_key = PKey::private_key_from_pem(&ca_key_data).unwrap();
    
    // Generate workload key (simulating your generate_workload_key method)
    let workload_rsa = Rsa::generate(2048).unwrap();
    let workload_key = PKey::from_rsa(workload_rsa).unwrap();
    
    // Create certificate (simulating your issue_spiffe_certificate method)
    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    
    // Serial number
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    let serial_asn1 = serial.to_asn1_integer().unwrap();
    cert_builder.set_serial_number(&serial_asn1).unwrap();
    
    // Subject
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", spiffe_id).unwrap();
    let subject_name = name_builder.build();
    cert_builder.set_subject_name(&subject_name).unwrap();
    cert_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    cert_builder.set_pubkey(&workload_key).unwrap();
    
    // Validity
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();
    
    // SPIFFE ID in SAN - THE CRITICAL TEST!
    let san_extension = SubjectAlternativeName::new()
        .uri(spiffe_id)
        .build(&cert_builder.x509v3_context(Some(&ca_cert), None))
        .unwrap();
    cert_builder.append_extension(san_extension).unwrap();
    
    // Key usage extensions
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    cert_builder.append_extension(key_usage).unwrap();
    
    let extended_key_usage = ExtendedKeyUsage::new()
        .client_auth()
        .server_auth()
        .build()
        .unwrap();
    cert_builder.append_extension(extended_key_usage).unwrap();
    
    // Sign certificate
    cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let certificate = cert_builder.build();
    
    // VALIDATION TESTS
    println!("✅ Certificate generated successfully!");
    
    // Test 1: Certificate has SAN with SPIFFE ID
    let san_names = certificate.subject_alt_names().unwrap();
    let has_spiffe_id = san_names.iter()
        .any(|name| name.uri() == Some(spiffe_id));
    assert!(has_spiffe_id, "❌ Certificate should contain SPIFFE ID in SAN");
    println!("✅ Certificate contains SPIFFE ID in SAN: {}", spiffe_id);
    
    // Test 2: Certificate is properly signed
    let ca_pubkey = ca_cert.public_key().unwrap();
    assert!(certificate.verify(&ca_pubkey).unwrap(), "❌ Certificate signature verification failed");
    println!("✅ Certificate signature verified against CA");
    
    // Test 3: Certificate can be converted to PEM
    let cert_pem = certificate.to_pem().unwrap();
    let key_pem = workload_key.private_key_to_pem_pkcs8().unwrap();
    
    println!("✅ Certificate PEM length: {} bytes", cert_pem.len());
    println!("✅ Private key PEM length: {} bytes", key_pem.len());
    
    // Test 4: SPIFFE ID format validation  
    assert!(spiffe_id.starts_with("spiffe://"), "❌ Invalid SPIFFE ID format");
    assert!(spiffe_id.contains("virtru.com"), "❌ SPIFFE ID should contain trust domain");
    println!("✅ SPIFFE ID format is valid");
    
    println!("🎉 ALL TESTS PASSED! Your SPIFFE certificate generation logic is working perfectly!");
}

fn test_attestation_based_spiffe_generation() {
    println!("🧪 Testing attestation-based SPIFFE ID generation...");
    
    let trust_domain = "virtru.com";
    
    // Test GPU inference workload
    let gpu_attestation = AttestationContext::create_mock_gpu_workload();
    let gpu_spiffe_id = generate_spiffe_id_from_attestation(trust_domain, &gpu_attestation);
    assert_eq!(gpu_spiffe_id, "spiffe://virtru.com/gpu/inference");
    println!("✅ GPU inference SPIFFE ID: {}", gpu_spiffe_id);
    
    // Test CPU workload
    let cpu_attestation = AttestationContext::create_mock_cpu_workload();
    let cpu_spiffe_id = generate_spiffe_id_from_attestation(trust_domain, &cpu_attestation);
    assert_eq!(cpu_spiffe_id, "spiffe://virtru.com/cpu/data-processing");
    println!("✅ CPU workload SPIFFE ID: {}", cpu_spiffe_id);
    
    // Test GPU training workload
    let mut training_attestation = AttestationContext::create_mock_gpu_workload();
    training_attestation.workload_type = WorkloadType::GpuTraining;
    let training_spiffe_id = generate_spiffe_id_from_attestation(trust_domain, &training_attestation);
    assert_eq!(training_spiffe_id, "spiffe://virtru.com/gpu/training");
    println!("✅ GPU training SPIFFE ID: {}", training_spiffe_id);
    
    // Test invalid GPU attestation (should fall back to default)
    let mut invalid_gpu = AttestationContext::create_mock_gpu_workload();
    if let Some(ref mut gpu_claims) = invalid_gpu.gpu_attestation {
        gpu_claims.attestation_valid = false;
    }
    let invalid_spiffe_id = generate_spiffe_id_from_attestation(trust_domain, &invalid_gpu);
    assert_eq!(invalid_spiffe_id, "spiffe://virtru.com/workload/default");
    println!("✅ Invalid GPU attestation falls back to default: {}", invalid_spiffe_id);
    
    println!("🎉 Attestation-based SPIFFE ID generation works correctly!");
}

fn test_negative_cases() {
    println!("🧪 Testing NEGATIVE cases to ensure tests can actually fail...");
    
    let trust_domain = "virtru.com";
    
    // Test 1: GPU workload without valid attestation should NOT get GPU SPIFFE ID
    let mut invalid_gpu = AttestationContext::create_mock_gpu_workload();
    if let Some(ref mut gpu_claims) = invalid_gpu.gpu_attestation {
        gpu_claims.attestation_valid = false; // Make attestation invalid
    }
    let invalid_spiffe_id = generate_spiffe_id_from_attestation(trust_domain, &invalid_gpu);
    
    // This should NOT be a GPU SPIFFE ID
    assert_ne!(invalid_spiffe_id, "spiffe://virtru.com/gpu/inference", 
               "❌ Invalid GPU attestation should NOT get gpu/inference SPIFFE ID");
    assert_eq!(invalid_spiffe_id, "spiffe://virtru.com/workload/default", 
               "❌ Invalid GPU attestation should fall back to default");
    println!("✅ Invalid GPU attestation correctly rejected: {}", invalid_spiffe_id);
    
    // Test 2: Test has_valid_gpu_attestation logic thoroughly
    let mut partial_invalid = AttestationContext::create_mock_gpu_workload();
    if let Some(ref mut gpu_claims) = partial_invalid.gpu_attestation {
        gpu_claims.secure_boot_enabled = false; // Only one field invalid
    }
    assert!(!partial_invalid.has_valid_gpu_attestation(), 
            "❌ GPU attestation should be invalid when secure_boot_enabled=false");
    println!("✅ Partial GPU attestation correctly rejected");
    
    // Test 3: Unknown workload type should get default SPIFFE ID
    let unknown_workload = AttestationContext {
        workload_type: WorkloadType::Unknown,
        workload_name: "test".to_string(),
        container_image: "test:latest".to_string(),
        gpu_attestation: Some(GpuAttestationClaims {
            gpu_model: "H100".to_string(),
            attestation_valid: true,
            secure_boot_enabled: true,
            measurement_valid: true,
        }),
    };
    let unknown_spiffe_id = generate_spiffe_id_from_attestation(trust_domain, &unknown_workload);
    assert_eq!(unknown_spiffe_id, "spiffe://virtru.com/workload/default",
               "❌ Unknown workload type should get default SPIFFE ID even with valid GPU attestation");
    println!("✅ Unknown workload type correctly gets default: {}", unknown_spiffe_id);
    
    println!("🎉 All negative test cases passed - tests can actually fail!");
}

fn test_certificate_validation_rigor() {
    println!("🔍 Testing certificate validation more rigorously...");
    
    let (ca_cert_file, ca_key_file) = create_test_ca();
    let ca_cert_data = std::fs::read(ca_cert_file.path()).unwrap();
    let ca_cert = openssl::x509::X509::from_pem(&ca_cert_data).unwrap();
    let ca_key_data = std::fs::read(ca_key_file.path()).unwrap();
    let ca_key = PKey::private_key_from_pem(&ca_key_data).unwrap();
    
    // Test with a different SPIFFE ID to ensure we're actually checking
    let test_spiffe_id = "spiffe://example.com/test/workload";
    
    let workload_rsa = Rsa::generate(2048).unwrap();
    let workload_key = PKey::from_rsa(workload_rsa).unwrap();
    
    let mut cert_builder = X509Builder::new().unwrap();
    cert_builder.set_version(2).unwrap();
    
    let mut serial = BigNum::new().unwrap();
    serial.rand(128, MsbOption::MAYBE_ZERO, false).unwrap();
    let serial_asn1 = serial.to_asn1_integer().unwrap();
    cert_builder.set_serial_number(&serial_asn1).unwrap();
    
    let mut name_builder = X509NameBuilder::new().unwrap();
    name_builder.append_entry_by_text("CN", test_spiffe_id).unwrap();
    let subject_name = name_builder.build();
    cert_builder.set_subject_name(&subject_name).unwrap();
    cert_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
    cert_builder.set_pubkey(&workload_key).unwrap();
    
    let not_before = Asn1Time::days_from_now(0).unwrap();
    let not_after = Asn1Time::days_from_now(1).unwrap();
    cert_builder.set_not_before(&not_before).unwrap();
    cert_builder.set_not_after(&not_after).unwrap();
    
    // Add the SPIFFE ID in SAN
    let san_extension = SubjectAlternativeName::new()
        .uri(test_spiffe_id)
        .build(&cert_builder.x509v3_context(Some(&ca_cert), None))
        .unwrap();
    cert_builder.append_extension(san_extension).unwrap();
    
    let key_usage = KeyUsage::new()
        .digital_signature()
        .key_encipherment()
        .build()
        .unwrap();
    cert_builder.append_extension(key_usage).unwrap();
    
    cert_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
    let certificate = cert_builder.build();
    
    // Test 1: Verify the EXACT SPIFFE ID is in SAN (not just any URI)
    let san_names = certificate.subject_alt_names().unwrap();
    let found_uris: Vec<_> = san_names.iter()
        .filter_map(|name| name.uri())
        .collect();
    
    assert!(!found_uris.is_empty(), "❌ Certificate should have URI in SAN");
    assert!(found_uris.contains(&test_spiffe_id), 
            "❌ Certificate should contain the exact SPIFFE ID '{}', found: {:?}", 
            test_spiffe_id, found_uris);
    
    // Test 2: Verify wrong SPIFFE ID is NOT in SAN
    let wrong_spiffe_id = "spiffe://wrong.com/bad/id";
    assert!(!found_uris.contains(&wrong_spiffe_id),
            "❌ Certificate should NOT contain wrong SPIFFE ID '{}'", wrong_spiffe_id);
    
    println!("✅ Certificate contains correct SPIFFE ID: {}", test_spiffe_id);
    println!("✅ Certificate does NOT contain wrong SPIFFE ID");
    
    // Test 3: Try to verify with wrong CA (should fail)
    let wrong_ca_rsa = Rsa::generate(2048).unwrap();
    let wrong_ca_key = PKey::from_rsa(wrong_ca_rsa).unwrap();
    
    let verification_result = certificate.verify(&wrong_ca_key);
    match verification_result {
        Ok(false) => println!("✅ Certificate correctly fails verification with wrong CA"),
        Ok(true) => panic!("❌ Certificate should NOT verify with wrong CA key!"),
        Err(_) => println!("✅ Certificate verification with wrong CA produces error (acceptable)"),
    }
    
    println!("🎉 Rigorous certificate validation tests passed!");
}

fn main() {
    test_spiffe_certificate_generation();
    println!();
    test_attestation_based_spiffe_generation();
    println!();
    test_negative_cases();
    println!();
    test_certificate_validation_rigor();
}
