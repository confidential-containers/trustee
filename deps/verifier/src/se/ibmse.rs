// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{ReportData, TeeEvidence, TeeEvidenceParsedClaim, ToHex};
use anyhow::{anyhow, Context, Result};
use core::result::Result::Ok;
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use pv::attest::{
    AdditionalData, AttestationFlags, AttestationItems, AttestationMeasAlg, AttestationMeasurement,
    AttestationRequest, AttestationVersion,
};
use pv::misc::{open_file, read_certs};
use pv::request::{BootHdrTags, CertVerifier, HkdVerifier, ReqEncrCtx, Request, SymKeyType};
use pv::uv::ConfigUid;
use serde::{Deserialize, Serialize};
use serde_with::{base64::Base64, hex::Hex, serde_as};
use std::{env, fs};
use thiserror::Error;
use tracing::{debug, info, warn};

const DEFAULT_CERTS_OFFLINE_VERIFICATION: &str = "false";

const DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT: &str = "/run/confidential-containers/ibmse/hkds";

const DEFAULT_SE_CERTIFICATES_ROOT: &str = "/run/confidential-containers/ibmse/certs";

const DEFAULT_SE_CERTIFICATE_ROOT_CA: &str = "/run/confidential-containers/ibmse/root_ca.crt";

const DEFAULT_SE_CERTIFICATE_REVOCATION_LISTS_ROOT: &str =
    "/run/confidential-containers/ibmse/crls";

const DEFAULT_SE_IMAGE_HEADER_FILE: &str = "/run/confidential-containers/ibmse/hdr/hdr.bin";

const DEFAULT_SE_MEASUREMENT_ENCR_KEY_PRIVATE: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pem";

const DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pub";

macro_rules! env_or_default {
    ($env:literal, $default:ident) => {
        match env::var($env) {
            Ok(env_path) => env_path,
            Err(_) => $default.into(),
        }
    };
}

fn list_files_in_folder(dir: &str) -> Result<Vec<String>> {
    let mut file_paths = Vec::new();

    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() {
            if let Some(path_str) = path.to_str() {
                file_paths.push(path_str.to_string());
            }
        }
    }

    Ok(file_paths)
}

/// Error types for SE verifier operations
#[derive(Error, Debug)]
pub enum SeError {
    #[error(
        "USER_DATA content mismatch in IBM SEL evidence, expected: {expected:?}, got: {actual:?}"
    )]
    UserDataMismatch { expected: Vec<u8>, actual: Vec<u8> },

    #[error("Failed to verify the measurement")]
    MeasurementVerificationFailed,

    #[error("Failed to decrypt measurement key")]
    DecryptMeasurementKey(#[source] anyhow::Error),

    #[error("Failed to decrypt request nonce")]
    DecryptRequestNonce(#[source] anyhow::Error),

    #[error("Failed to convert nonce from Vec<u8> to [u8; 16], must have exactly 16 elements")]
    InvalidNonceLength,

    #[error("Failed to get image_public_host_key_hash")]
    MissingImagePublicHostKeyHash,

    #[error("Failed to get attestation_public_host_key_hash")]
    MissingAttestationPublicHostKeyHash,

    #[error("Failed to deserialize evidence")]
    DeserializeEvidence(#[source] serde_json::Error),

    #[error("Failed to build json value from SE claims")]
    BuildJsonClaims(#[source] serde_json::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationResponse {
    #[serde_as(as = "Base64")]
    measurement: Vec<u8>,
    #[serde_as(as = "Base64")]
    additional_data: Vec<u8>,
    #[serde_as(as = "Base64")]
    user_data: Vec<u8>,
    #[serde_as(as = "Base64")]
    cuid: ConfigUid,
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationClaims {
    #[serde_as(as = "Hex")]
    cuid: ConfigUid,
    report_data: String,
    version: u32,
    #[serde_as(as = "Hex")]
    image_phkh: Vec<u8>,
    #[serde_as(as = "Hex")]
    attestation_phkh: Vec<u8>,
    #[serde_as(as = "Hex")]
    tag: [u8; 16],
}

#[repr(C)]
#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct SeAttestationRequest {
    #[serde_as(as = "Base64")]
    request_blob: Vec<u8>,
    measurement_size: u32,
    additional_size: u32,
    #[serde_as(as = "Base64")]
    encr_measurement_key: Vec<u8>,
    #[serde_as(as = "Base64")]
    encr_request_nonce: Vec<u8>,
    #[serde_as(as = "Base64")]
    image_hdr_tags: BootHdrTags,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde_as(as = "Option<Base64>")]
    runtime_data_digest: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct SeVerifierImpl {
    private_key: PKey<Private>,
    public_key: PKey<Public>,
}

impl SeVerifierImpl {
    pub fn new() -> Result<Self> {
        let pri_key_file = env_or_default!(
            "SE_MEASUREMENT_ENCR_KEY_PRIVATE",
            DEFAULT_SE_MEASUREMENT_ENCR_KEY_PRIVATE
        );
        let priv_contents = fs::read(pri_key_file)?;
        let private_key = PKey::private_key_from_pem(&priv_contents)?;

        let pub_key_file = env_or_default!(
            "SE_MEASUREMENT_ENCR_KEY_PUBLIC",
            DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC
        );
        let pub_contents = fs::read(pub_key_file)?;
        let public_key = PKey::public_key_from_pem(&pub_contents)?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let mut decrypter = Decrypter::new(&self.private_key)?;
        decrypter.set_rsa_padding(Padding::PKCS1)?;

        let buffer_len = decrypter.decrypt_len(ciphertext)?;
        let mut decrypted = vec![0; buffer_len];
        let decrypted_len = decrypter.decrypt(ciphertext, &mut decrypted)?;
        decrypted.truncate(decrypted_len);

        Ok(decrypted)
    }

    fn encrypt(&self, text: &[u8]) -> Result<Vec<u8>> {
        let mut encrypter = Encrypter::new(&self.public_key)?;
        encrypter.set_rsa_padding(Padding::PKCS1)?;

        let buffer_len = encrypter.encrypt_len(text)?;
        let mut encrypted = vec![0; buffer_len];
        let len = encrypter.encrypt(text, &mut encrypted)?;
        encrypted.truncate(len);

        Ok(encrypted)
    }

    pub fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
    ) -> Result<TeeEvidenceParsedClaim> {
        info!("IBM SE verify API called.");

        // evidence is serialized SeAttestationResponse String bytes
        let se_response: SeAttestationResponse =
            serde_json::from_value(evidence).map_err(SeError::DeserializeEvidence)?;

        let meas_key = self
            .decrypt(&se_response.encr_measurement_key)
            .map_err(SeError::DecryptMeasurementKey)?;
        let nonce = self
            .decrypt(&se_response.encr_request_nonce)
            .map_err(SeError::DecryptRequestNonce)?;

        let nonce_array: [u8; 16] = nonce.try_into().map_err(|_| SeError::InvalidNonceLength)?;

        // Validate runtime_data_digest if provided
        if let ReportData::Value(expected_report_data) = expected_report_data {
            let report_data = se_response
                .user_data
                .get(..48)
                .context("Failed to get report_data section from USER_DATA")?;
            if report_data != *expected_report_data {
                return Err(SeError::UserDataMismatch {
                    expected: expected_report_data.to_vec(),
                    actual: report_data.to_vec(),
                }
                .into());
            }
        } else {
            info!("No expected runtime_data_digest provided for IBM SEL verification, skipping user_data validation");
        }

        let meas_key = PKey::hmac(&meas_key)?;
        let items = AttestationItems::new(
            &se_response.image_hdr_tags,
            &se_response.cuid,
            Some(&se_response.user_data),
            Some(&nonce_array),
            Some(&se_response.additional_data),
        );

        let measurement =
            AttestationMeasurement::calculate(items, AttestationMeasAlg::HmacSha512, &meas_key)?;

        if !measurement.eq_secure(&se_response.measurement) {
            debug!("Recieved: {:?}", se_response.measurement);
            debug!("Calculated: {:?}", measurement.as_ref());
            return Err(SeError::MeasurementVerificationFailed.into());
        }

        let mut att_flags = AttestationFlags::default();
        att_flags.set_image_phkh();
        att_flags.set_attest_phkh();
        let add_data = AdditionalData::from_slice(&se_response.additional_data, &att_flags)?;
        debug!("additional_data: {:?}", add_data);
        let image_phkh = add_data
            .image_public_host_key_hash()
            .ok_or(SeError::MissingImagePublicHostKeyHash)?;
        let attestation_phkh = add_data
            .attestation_public_host_key_hash()
            .ok_or(SeError::MissingAttestationPublicHostKeyHash)?;

        let claims = SeAttestationClaims {
            cuid: se_response.cuid,
            report_data: expected_report_data.to_hex(),
            version: AttestationVersion::One as u32,
            image_phkh: image_phkh.to_vec(),
            attestation_phkh: attestation_phkh.to_vec(),
            tag: *se_response.image_hdr_tags.tag(),
        };

        Ok(serde_json::to_value(claims).map_err(SeError::BuildJsonClaims)?)
    }

    pub async fn generate_supplemental_challenge(&self, _tee_parameters: String) -> Result<String> {
        let se_certificate_root =
            env_or_default!("SE_CERTIFICATES_ROOT", DEFAULT_SE_CERTIFICATES_ROOT);
        let ca_certs = list_files_in_folder(&se_certificate_root)?;

        let crl_root = env_or_default!(
            "SE_CERTIFICATE_REVOCATION_LISTS_ROOT",
            DEFAULT_SE_CERTIFICATE_REVOCATION_LISTS_ROOT
        );
        let crls = list_files_in_folder(&crl_root)?;

        let root_ca_path =
            env_or_default!("SE_CERTIFICATE_ROOT_CA", DEFAULT_SE_CERTIFICATE_ROOT_CA);
        let ca_option: Option<String> = if std::path::Path::new(&root_ca_path).exists() {
            Some(root_ca_path)
        } else {
            None::<String>
        };
        let offline_certs_verify = env_or_default!(
            "CERTS_OFFLINE_VERIFICATION",
            DEFAULT_CERTS_OFFLINE_VERIFICATION
        );
        let offline_certs_verify: bool = offline_certs_verify.parse::<bool>().unwrap_or(false);
        let mut attestation_flags = AttestationFlags::default();
        attestation_flags.set_image_phkh();
        attestation_flags.set_attest_phkh();
        let mut arcb = AttestationRequest::new(
            AttestationVersion::One,
            AttestationMeasAlg::HmacSha512,
            attestation_flags,
        )?;

        let hkds_root = env_or_default!(
            "DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT",
            DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT
        );
        let hkds = list_files_in_folder(&hkds_root)?;
        for hkd in &hkds {
            let hk = std::fs::read(hkd).context("read host-key document")?;
            let certs = read_certs(&hk)?;
            if certs.is_empty() {
                warn!("The host key document in '{hkd}' contains empty certificate!");
            }
            if certs.len() != 1 {
                warn!("The host key document in '{hkd}' contains more than one certificate!")
            }
            let c = certs
                .first()
                .ok_or(anyhow!("File does not contain a X509 certificate"))?;
            const DEFAULT_SE_SKIP_CERTS_VERIFICATION: &str = "false";
            let skip_certs_env = env_or_default!(
                "SE_SKIP_CERTS_VERIFICATION",
                DEFAULT_SE_SKIP_CERTS_VERIFICATION
            );
            let skip_certs: bool = skip_certs_env.parse::<bool>().unwrap_or(false);
            if !skip_certs {
                let verifier = CertVerifier::new(
                    ca_certs.as_slice(),
                    crls.as_slice(),
                    ca_option.clone(),
                    offline_certs_verify,
                )?;
                verifier.verify(c)?;
            }
            arcb.add_hostkey(c.public_key()?);
        }

        let encr_ctx = ReqEncrCtx::random(SymKeyType::Aes256Gcm)?;
        let request_blob = arcb.encrypt(&encr_ctx)?;
        let conf_data = arcb.confidential_data();
        let encr_measurement_key = self.encrypt(conf_data.measurement_key())?;
        let nonce = conf_data
            .nonce()
            .as_ref()
            .ok_or(anyhow!("Failed to get nonce binding"))?
            .value();
        let encr_request_nonce = self.encrypt(nonce)?;

        let se_img_hdr = env_or_default!("SE_IMAGE_HEADER_FILE", DEFAULT_SE_IMAGE_HEADER_FILE);
        let mut hdr_file = open_file(se_img_hdr)?;
        let image_hdr_tags = BootHdrTags::from_se_image(&mut hdr_file)?;

        let se_attestation_request = SeAttestationRequest {
            request_blob,
            measurement_size: AttestationMeasAlg::HmacSha512.exp_size(),
            additional_size: arcb.flags().expected_additional_size(),
            encr_measurement_key,
            encr_request_nonce,
            image_hdr_tags,
            runtime_data_digest: None,
        };

        let challenge = serde_json::to_string(&se_attestation_request)?;
        Ok(challenge)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use pv::request::BootHdrTags;
    use pv::uv::ConfigUid;

    // Helper to generate test RSA key pair
    fn generate_test_keypair() -> (PKey<Private>, PKey<Public>) {
        let rsa = Rsa::generate(2048).expect("Failed to generate RSA key");
        let private_key = PKey::from_rsa(rsa.clone()).expect("Failed to create private key");
        // Extract public key from the RSA key
        let public_key = PKey::from_rsa(
            Rsa::from_public_components(
                rsa.n().to_owned().expect("Failed to get n"),
                rsa.e().to_owned().expect("Failed to get e"),
            )
            .expect("Failed to create public RSA"),
        )
        .expect("Failed to create public key");
        (private_key, public_key)
    }

    // Helper to create a test SeVerifierImpl with generated keys
    fn create_test_verifier() -> SeVerifierImpl {
        let (private_key, public_key) = generate_test_keypair();
        SeVerifierImpl {
            private_key,
            public_key,
        }
    }

    // Helper to create a dummy BootHdrTags for testing
    fn create_dummy_boot_hdr_tags() -> BootHdrTags {
        // BootHdrTags::new signature: (pld: [u8; 64], ald: [u8; 64], tld: [u8; 64], tag: [u8; 16])
        let pld = [0u8; 64];
        let ald = [0u8; 64];
        let tld = [0u8; 64];
        let tag = [0u8; 16];
        BootHdrTags::new(pld, ald, tld, tag)
    }

    // Helper to create a dummy ConfigUid for testing
    fn create_dummy_config_uid() -> ConfigUid {
        // ConfigUid is a type alias for [u8; 16]
        [0u8; 16]
    }

    /// Test user_data validation when report_data is provided and matches
    #[test]
    fn test_user_data_validation_success() {
        let verifier = create_test_verifier();

        // Create test data - SHA-384 is 48 bytes
        let report_data = vec![0x05; 48];

        // Build user_data: first 48 bytes are report_data, rest can be anything
        let mut user_data = report_data.clone();
        user_data.extend_from_slice(&[0xAA; 16]); // Add some extra data

        let nonce = vec![0x09; 16];
        let meas_key = vec![0x0A; 32];

        let encr_nonce = verifier.encrypt(&nonce).expect("Failed to encrypt nonce");
        let encr_key = verifier.encrypt(&meas_key).expect("Failed to encrypt key");

        let response = SeAttestationResponse {
            measurement: vec![0x0B; 64],
            additional_data: vec![],
            user_data,
            cuid: create_dummy_config_uid(),
            encr_measurement_key: encr_key,
            encr_request_nonce: encr_nonce,
            image_hdr_tags: create_dummy_boot_hdr_tags(),
        };

        let evidence = serde_json::to_value(&response).expect("Failed to serialize");
        let expected_report_data = ReportData::Value(&report_data);

        let result = verifier.evaluate(evidence, &expected_report_data);

        // Should fail at measurement verification (we don't have valid measurement),
        // but NOT at user_data validation
        assert!(result.is_err(), "Should fail at measurement verification");
        let err = result.unwrap_err();

        // Check that the error is NOT a UserDataMismatch
        if let Some(se_error) = err.downcast_ref::<SeError>() {
            assert!(
                !matches!(se_error, SeError::UserDataMismatch { .. }),
                "Should not fail at USER_DATA validation, got: {:?}",
                se_error
            );
        }
    }

    /// Test user_data validation when user_data doesn't match expected values
    #[test]
    fn test_user_data_validation_mismatch() {
        let verifier = create_test_verifier();

        // Create test data - SHA-384 is 48 bytes
        let report_data = vec![0x05; 48];

        // Build user_data with WRONG report_data in first 48 bytes
        let mut user_data = vec![0xFF; 48]; // Wrong report data
        user_data.extend_from_slice(&[0xAA; 16]); // Add some extra data

        let nonce = vec![0x09; 16];
        let meas_key = vec![0x0A; 32];

        let encr_nonce = verifier.encrypt(&nonce).expect("Failed to encrypt nonce");
        let encr_key = verifier.encrypt(&meas_key).expect("Failed to encrypt key");

        let response = SeAttestationResponse {
            measurement: vec![0x0B; 64],
            additional_data: vec![],
            user_data,
            cuid: create_dummy_config_uid(),
            encr_measurement_key: encr_key,
            encr_request_nonce: encr_nonce,
            image_hdr_tags: create_dummy_boot_hdr_tags(),
        };

        let evidence = serde_json::to_value(&response).expect("Failed to serialize");
        let expected_report_data = ReportData::Value(&report_data);

        let result = verifier.evaluate(evidence, &expected_report_data);

        assert!(result.is_err(), "Should fail with mismatched user_data");
        let err = result.unwrap_err();

        // Check that the error IS a UserDataMismatch
        let se_error = err
            .downcast_ref::<SeError>()
            .expect("Error should be an SeError");
        assert!(
            matches!(se_error, SeError::UserDataMismatch { .. }),
            "Error should be UserDataMismatch, got: {:?}",
            se_error
        );
    }

    /// Test user_data validation when no expected values are provided
    #[test]
    fn test_user_data_validation_no_expected_values() {
        let verifier = create_test_verifier();

        // Build user_data with some report_data
        let report_data = vec![0x05; 48];
        let mut user_data = report_data.clone();
        user_data.extend_from_slice(&[0xBB; 16]);

        let nonce = vec![0x09; 16];
        let meas_key = vec![0x0A; 32];

        let encr_nonce = verifier.encrypt(&nonce).expect("Failed to encrypt nonce");
        let encr_key = verifier.encrypt(&meas_key).expect("Failed to encrypt key");

        let response = SeAttestationResponse {
            measurement: vec![0x0B; 64],
            additional_data: vec![],
            user_data,
            cuid: create_dummy_config_uid(),
            encr_measurement_key: encr_key,
            encr_request_nonce: encr_nonce,
            image_hdr_tags: create_dummy_boot_hdr_tags(),
        };

        let evidence = serde_json::to_value(&response).expect("Failed to serialize");
        let expected_report_data = ReportData::NotProvided;

        let result = verifier.evaluate(evidence, &expected_report_data);

        // Should fail at measurement verification, but NOT at user_data validation
        assert!(result.is_err(), "Should fail at measurement verification");
        let err = result.unwrap_err();

        // Check that the error is NOT a UserDataMismatch
        if let Some(se_error) = err.downcast_ref::<SeError>() {
            assert!(
                !matches!(se_error, SeError::UserDataMismatch { .. }),
                "Should not fail at USER_DATA validation when no expected values provided, got: {:?}",
                se_error
            );
        }
    }
}
