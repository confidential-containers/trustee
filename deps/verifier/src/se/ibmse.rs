// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{regularize_data, ReportData, TeeEvidence, TeeEvidenceParsedClaim, ToHex};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
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
use std::{collections::HashSet, env, fs, time::Duration};
use thiserror::Error;
use tokio::{sync::RwLock, time::sleep};
use tracing::{debug, info, warn};

const DEFAULT_CERTS_OFFLINE_VERIFICATION: &str = "false";

/// Size of report data in IBM SE attestation (64 bytes)
const SE_REPORT_DATA_SIZE: usize = 64;

/// Size of the firmware state returned by the Ultravisor.
const FIRMWARE_STATE_SIZE: usize = 320;

const FIRMWARE_VERIFY_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRIES: u32 = 10;
const RETRY_DELAY: Duration = Duration::from_secs(3);

const FIRMWARE_CLIENT_ID_HEADER_VALUE: &str = "X";

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

    #[error("Failed to get firmware_state from additional_data")]
    MissingFirmwareState,

    #[error("Malformed firmware_state: expected {expected} bytes but got {actual} bytes from UV")]
    MalformedFirmwareState { expected: usize, actual: usize },

    #[error("Firmware verification failed: {0}")]
    FirmwareVerificationFailed(String),

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
    config: super::SeVerifierConfig,
    firmware_cache: RwLock<HashSet<String>>,
    http_client: reqwest::Client,
}

impl SeVerifierImpl {
    pub fn new(config: Option<super::SeVerifierConfig>) -> Result<Self> {
        let mut config = config.unwrap_or_default();

        // Allow env var to override toml config without recompiling.
        if let Ok(val) = env::var("SE_ENABLE_FIRMWARE_VERIFICATION") {
            config.enable_firmware_verification = val.trim().eq_ignore_ascii_case("true");
            info!(
                "SE_ENABLE_FIRMWARE_VERIFICATION env var overrides config: enable_firmware_verification={}",
                config.enable_firmware_verification
            );
        }

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

        let http_client = reqwest::Client::builder()
            .timeout(FIRMWARE_VERIFY_TIMEOUT)
            .user_agent("s390-tools-pvattest")
            .build()
            .context("Failed to create firmware verification HTTP client")?;

        Ok(Self {
            private_key,
            public_key,
            config,
            firmware_cache: RwLock::new(HashSet::new()),
            http_client,
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

    /// Verify the 320-byte firmware hash against the IBM firmware attestation API.
    /// Constructs a JSON POST request and checks the `valid` field in the response.
    /// Returns Ok(()) if firmware is valid, Err if not or if the API call fails.
    async fn verify_firmware(&self, firmware_hash: &[u8]) -> Result<()> {
        #[derive(Serialize)]
        struct FwRequest {
            version: String,
            payload: String,
        }

        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct VerifiedHash {
            hash: String,
            signature: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct FwResponse {
            valid: bool,
            reference_id: String,
            #[serde(default)]
            reason: Option<String>,
            #[serde(default)]
            #[allow(dead_code)]
            verified_hashes: Option<Vec<VerifiedHash>>,
        }

        let url = &self.config.firmware_verify_url;
        let hash_b64 = BASE64.encode(firmware_hash);
        let body = FwRequest {
            version: "1.0".to_string(),
            payload: hash_b64.clone(),
        };

        // Return immediately if this hash was already verified successfully.
        if self.firmware_cache.read().await.contains(&hash_b64) {
            debug!("Firmware hash found in cache, skipping API call");
            return Ok(());
        }

        for attempt in 1..=MAX_RETRIES {
            debug!("POST firmware verification to {url} (attempt {attempt}/{MAX_RETRIES})");

            let resp = self
                .http_client
                .post(url)
                .header("x-client-id", FIRMWARE_CLIENT_ID_HEADER_VALUE)
                .json(&body)
                .send()
                .await
                .context("Failed to send firmware verification request")?;

            if !resp.status().is_success() {
                return Err(SeError::FirmwareVerificationFailed(format!(
                    "API returned HTTP {}",
                    resp.status()
                ))
                .into());
            }

            let result: FwResponse = resp
                .json()
                .await
                .context("Failed to parse firmware verification response")?;

            // Store the firmware hash in the cache after successful verification.
            // On subsequent runs, the cache is checked first to avoid another API call.
            if result.valid {
                info!(
                    "Firmware verification passed (referenceId: {})",
                    result.reference_id
                );
                self.firmware_cache.write().await.insert(hash_b64);
                return Ok(());
            }
            debug!("Firmware response received from the api call: {:?}", result);
            let reason = result
                .reason
                .unwrap_or_else(|| format!("referenceId: {}", result.reference_id));
            warn!("Firmware verification attempt {attempt}/{MAX_RETRIES} not yet valid: {reason}");

            if attempt < MAX_RETRIES {
                sleep(RETRY_DELAY).await;
            }
        }

        Err(SeError::FirmwareVerificationFailed(format!(
            "firmware not valid after {MAX_RETRIES} attempts"
        ))
        .into())
    }

    pub async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData<'_>,
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
            let expected_report_data = regularize_data(
                expected_report_data,
                SE_REPORT_DATA_SIZE,
                "USER_DATA",
                "IBM SE",
            );
            let report_data = se_response
                .user_data
                .get(..expected_report_data.len())
                .context("Failed to get report_data section from USER_DATA")?;
            if report_data != expected_report_data {
                return Err(SeError::UserDataMismatch {
                    expected: expected_report_data,
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
        if se_response.additional_data.len() == SE_REPORT_DATA_SIZE + FIRMWARE_STATE_SIZE {
            att_flags.set_firmware_state();
        }
        let add_data = AdditionalData::from_slice(&se_response.additional_data, &att_flags)?;
        debug!("additional_data: {:?}", add_data);
        let image_phkh = add_data
            .image_public_host_key_hash()
            .ok_or(SeError::MissingImagePublicHostKeyHash)?;
        let attestation_phkh = add_data
            .attestation_public_host_key_hash()
            .ok_or(SeError::MissingAttestationPublicHostKeyHash)?;

        let firmware_hash: Option<Vec<u8>> = match add_data.firmware_state() {
            Some(fw_slice) if fw_slice.len() == FIRMWARE_STATE_SIZE => {
                debug!("Firmware hash present: {} bytes from UV", fw_slice.len());
                Some(fw_slice.to_vec())
            }
            Some(fw_slice) => {
                return Err(SeError::MalformedFirmwareState {
                    expected: FIRMWARE_STATE_SIZE,
                    actual: fw_slice.len(),
                }
                .into());
            }
            None => {
                debug!(
                    "No firmware state returned by UV; expected for z16 or earlier, \
                     or UV did not honour the firmware-state flag"
                );
                None
            }
        };

        // Decision table:
        // firmware_hash present  + enable_firmware_verification=true → verify firmware hash, attestation success
        // firmware_hash present  + enable_firmware_verification=false → skip verification, attestation success
        // firmware_hash absent   + enable_firmware_verification=true → skip verification, attestation success
        // firmware_hash absent   + enable_firmware_verification=false → skip verification, attestation success
        match (&firmware_hash, self.config.enable_firmware_verification) {
            (Some(hash), true) => {
                self.verify_firmware(hash).await?;
            }
            (Some(_), false) => {
                debug!("Firmware hash present but verification is disabled, skipping");
            }
            (None, true) => {
                warn!(
                    "Firmware verification is enabled but no firmware state was found; \
                     skipping firmware verification"
                );
            }
            (None, false) => {
                debug!("Firmware hash not present and verification is disabled, skipping");
            }
        }

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

    pub async fn generate_supplemental_challenge(&self, tee_parameters: String) -> Result<String> {
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

        let machine_type = machine_type_from_tee_parameters(&tee_parameters);
        debug!(
            "Detected machine type from tee_parameters: {:?}",
            machine_type
        );
        match machine_type.as_deref() {
            Some("z17") => {
                attestation_flags.set_firmware_state();
                info!("Firmware state flag set for z17 machine type");
            }
            Some(mt) => debug!("Firmware state flag NOT set for machine type: {}", mt),
            None => debug!("Firmware state flag NOT set: machine type not detected"),
        }

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

fn machine_type_from_tee_parameters(tee_parameters: &str) -> Option<String> {
    if tee_parameters.is_empty() {
        debug!("tee_parameters is empty, firmware state flag not set");
        return None;
    }
    let value = serde_json::from_str::<serde_json::Value>(tee_parameters).ok()?;
    value
        .get("machine-type")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::pkey::PKey;
    use openssl::rsa::Rsa;
    use pv::request::BootHdrTags;
    use pv::uv::ConfigUid;
    use rstest::rstest;

    // Size of image and attestation public-host-key hashes in additional_data.
    // Only needed in tests to build dummy attestation responses.
    const PHKH_ADDITIONAL_DATA_SIZE: usize = 64;

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
            config: crate::se::SeVerifierConfig::default(),
            firmware_cache: RwLock::new(HashSet::new()),
            http_client: reqwest::Client::new(),
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

    // Helper to create a SeVerifierImpl with explicit firmware-verification
    // setting and an optional mock server URL.
    fn create_verifier_with_config(
        enable_firmware_verification: bool,
        url: Option<&str>,
    ) -> SeVerifierImpl {
        let (private_key, public_key) = generate_test_keypair();
        SeVerifierImpl {
            private_key,
            public_key,
            config: crate::se::SeVerifierConfig {
                enable_firmware_verification,
                firmware_verify_url: url
                    .map(str::to_string)
                    .unwrap_or_else(|| crate::se::DEFAULT_FIRMWARE_VERIFY_URL.to_string()),
            },
            firmware_cache: RwLock::new(HashSet::new()),
            http_client: reqwest::Client::new(),
        }
    }

    const FW_REF_ID: &str = "70be38f2-cccd-4cb8-9cf5-8df1838320c1";

    /// Build a firmware API response body.
    fn fw_response_body(
        valid: bool,
        reason: &str,
        verified_hashes: Option<Vec<serde_json::Value>>,
    ) -> serde_json::Value {
        let version = if verified_hashes.is_some() {
            "2.0"
        } else {
            "1.0"
        };
        let mut body = serde_json::json!({
            "version": version,
            "valid": valid,
            "referenceId": FW_REF_ID,
            "reason": reason
        });
        if let Some(hashes) = verified_hashes {
            body["verifiedHashes"] = serde_json::json!(hashes);
        }
        body
    }

    /// Mount a v1 failure `valid:false` mock on `server` that fires exactly `times` times.
    async fn mount_fw_fail_mock(server: &wiremock::MockServer, reason: &str, times: u64) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(fw_response_body(false, reason, None)),
            )
            .up_to_n_times(times)
            .expect(times)
            .mount(server)
            .await;
    }

    // Mounts a success mock (valid:true) that fires exactly `times` times.
    // verified_hashes=None → v1 response (no verifiedHashes field, matches default endpoint).
    // verified_hashes=Some(..) → v2 response (verifiedHashes present).
    async fn mount_fw_success_mock(
        server: &wiremock::MockServer,
        times: u64,
        verified_hashes: Option<Vec<serde_json::Value>>,
    ) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};
        Mock::given(method("POST"))
            .and(path("/verify"))
            .respond_with(ResponseTemplate::new(200).set_body_json(fw_response_body(
                true,
                &format!("All hashes are valid, referenceId:{FW_REF_ID}"),
                verified_hashes,
            )))
            .up_to_n_times(times)
            .expect(times)
            .mount(server)
            .await;
    }

    // Helper to build a SeAttestationResponse with a valid HMAC measurement so
    // that evaluate() passes the measurement check and reaches the firmware branches.
    fn make_valid_response_with_firmware(
        verifier: &SeVerifierImpl,
        include_firmware_state: bool,
    ) -> SeAttestationResponse {
        let nonce = vec![0x09u8; 16];
        let meas_key_bytes = vec![0x0Au8; 32];
        let encr_nonce = verifier.encrypt(&nonce).expect("encrypt nonce");
        let encr_key = verifier.encrypt(&meas_key_bytes).expect("encrypt key");

        let user_data = vec![0u8; SE_REPORT_DATA_SIZE];
        let cuid = create_dummy_config_uid();
        let image_hdr_tags = create_dummy_boot_hdr_tags();

        // additional_data: 64 bytes PHKH (always) + optionally 320 bytes firmware state
        let mut additional_data = vec![0x01u8; PHKH_ADDITIONAL_DATA_SIZE];
        if include_firmware_state {
            additional_data.extend_from_slice(&[0x02u8; FIRMWARE_STATE_SIZE]);
        }

        // Compute the measurement the same way evaluate() does, so eq_secure() passes.
        let nonce_array: [u8; 16] = nonce.as_slice().try_into().expect("nonce must be 16 bytes");
        let items = AttestationItems::new(
            &image_hdr_tags,
            &cuid,
            Some(&user_data),
            Some(&nonce_array),
            Some(&additional_data),
        );
        let meas_key_pkey = openssl::pkey::PKey::hmac(&meas_key_bytes).expect("build HMAC key");
        let measurement = AttestationMeasurement::calculate(
            items,
            AttestationMeasAlg::HmacSha512,
            &meas_key_pkey,
        )
        .expect("calculate measurement");

        SeAttestationResponse {
            measurement: measurement.as_ref().to_vec(),
            additional_data,
            user_data,
            cuid,
            encr_measurement_key: encr_key,
            encr_request_nonce: encr_nonce,
            image_hdr_tags,
        }
    }

    fn assert_machine_type(params: &str, expected: Option<&str>) {
        assert_eq!(
            machine_type_from_tee_parameters(params),
            expected.map(str::to_owned),
            "input: {params:?}"
        );
    }

    #[test]
    fn machine_type_is_read_from_kbs_extra_params() {
        // known machine types
        assert_machine_type(r#"{"machine-type":"z17"}"#, Some("z17"));
        assert_machine_type(r#"{"machine-type":"z16"}"#, Some("z16"));

        // empty string value is returned as-is, not treated as absent
        assert_machine_type(r#"{"machine-type":""}"#, Some(""));

        // key absent or object empty → None
        assert_machine_type(r#"{"other-key":"z17"}"#, None);
        assert_machine_type(r#"{}"#, None);

        // non-string value (number, bool, null) → None
        assert_machine_type(r#"{"machine-type":42}"#, None);
        assert_machine_type(r#"{"machine-type":true}"#, None);
        assert_machine_type(r#"{"machine-type":null}"#, None);

        // invalid / empty input → None, must not panic
        assert_machine_type("", None);
        assert_machine_type("not-json", None);
    }

    /// Test user_data validation when report_data is provided and matches
    #[test]
    fn test_user_data_validation_success() {
        let verifier = create_test_verifier();

        // Create test data - SHA-512 is 64 bytes
        let report_data = vec![0x05; SE_REPORT_DATA_SIZE];

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

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(verifier.evaluate(evidence, &expected_report_data));

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

        // Create test data - SE report data is 64 bytes
        let report_data = vec![0x05; SE_REPORT_DATA_SIZE];

        // Build user_data with WRONG report_data
        let mut user_data = vec![0xFF; SE_REPORT_DATA_SIZE]; // Wrong report data
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

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(verifier.evaluate(evidence, &expected_report_data));

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
        let report_data = vec![0x05; SE_REPORT_DATA_SIZE];
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

        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(verifier.evaluate(evidence, &expected_report_data));

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

    // Firmware decision matrix — uses valid measurements so evaluate() reaches the
    // firmware branches.
    //
    // | fw_present | enable_fw | expected outcome                                      |
    // |------------|-----------|-------------------------------------------------------|
    // | true       | true      | verify_firmware called → Ok (mock returns valid:true) |
    // | true       | false     | firmware hash present but verification skipped → Ok   |
    // | false      | true      | no firmware state → Ok (verification skipped)         |
    // | false      | false     | no firmware state, verification disabled → Ok         |
    #[rstest]
    #[case::fw_present_verify_enabled(true, true)]
    #[case::fw_present_verify_disabled(true, false)]
    #[case::no_fw_verify_enabled(false, true)]
    #[case::no_fw_verify_disabled(false, false)]
    #[tokio::test]
    async fn firmware_decision_matrix(#[case] fw_present: bool, #[case] enable_fw: bool) {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        if fw_present && enable_fw {
            mount_fw_success_mock(&server, 1, None).await;
        }

        let url = format!("{}/verify", server.uri());
        let verifier = create_verifier_with_config(enable_fw, Some(&url));
        let response = make_valid_response_with_firmware(&verifier, fw_present);
        let evidence = serde_json::to_value(&response).expect("serialize");

        let result = verifier.evaluate(evidence, &ReportData::NotProvided).await;

        assert!(
            result.is_ok(),
            "fw_present={fw_present} enable_fw={enable_fw}: expected Ok, got: {:?}",
            result.unwrap_err()
        );

        if fw_present && enable_fw {
            server.verify().await;
        }
    }

    // ---------------------------------------------------------------------------
    // verify_firmware retry tests — wiremock stands in for the firmware API.
    //
    // Parameters:
    //   fail_count   – how many valid:false responses the mock emits
    //   v2_success   – if true the success response includes verifiedHashes (v2 API)
    //   expect_ok    – whether the call should return Ok(()) or Err
    //   payload_byte – single byte repeated to fill the 320-byte firmware hash
    // ---------------------------------------------------------------------------
    #[rstest]
    // Case 1: 1 failure then v1 success
    #[case::succeeds_on_second_attempt(1, false, true, 0xA1)]
    // Case 2: 2 failures then v2 success
    #[case::succeeds_on_third_attempt_v2(2, true, true, 0xB2)]
    // Case 3: all MAX_RETRIES failures → Err.
    #[case::fails_after_all_retries(MAX_RETRIES as usize, false, false, 0xC3)]
    // Case 4: MAX_RETRIES-1 failures then v1 success on the last attempt.
    #[case::succeeds_on_last_attempt((MAX_RETRIES - 1) as usize, false, true, 0xD4)]
    #[tokio::test]
    async fn fw_retry(
        #[case] fail_count: usize,
        #[case] v2_success: bool,
        #[case] expect_ok: bool,
        #[case] payload_byte: u8,
    ) {
        use wiremock::MockServer;
        let server = MockServer::start().await;

        for _ in 0..fail_count {
            mount_fw_fail_mock(&server, "Hash mismatch, referenceId:70be38f2", 1).await;
        }

        if expect_ok {
            let hashes = if v2_success {
                Some(vec![
                    serde_json::json!({"hash": "h1", "signature": "s1"}),
                    serde_json::json!({"hash": "h2", "signature": "s2"}),
                ])
            } else {
                None
            };
            mount_fw_success_mock(&server, 1, hashes).await;
        }

        let verifier = create_verifier_with_config(true, Some(&format!("{}/verify", server.uri())));
        let firmware_hash = vec![payload_byte; FIRMWARE_STATE_SIZE];
        let result = verifier.verify_firmware(&firmware_hash).await;

        if expect_ok {
            assert!(
                result.is_ok(),
                "expected Ok after {fail_count} failure(s), got: {result:?}"
            );
        } else {
            assert!(
                result.is_err(),
                "expected Err after all {MAX_RETRIES} retries"
            );
            let err_str = result.unwrap_err().to_string();
            assert!(
                err_str.contains("firmware not valid after"),
                "unexpected error message: {err_str}"
            );
        }

        server.verify().await;
    }
}
