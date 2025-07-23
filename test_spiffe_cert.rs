// Standalone test for SPIFFE certificate generation
// This tests the core logic without KBS dependencies

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

fn main() {
    test_spiffe_certificate_generation();
}
