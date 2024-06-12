// Copyright (C) Copyright IBM Corp. 2024
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::TeeEvidenceParsedClaim;
use anyhow::{anyhow, bail, Context, Result};
use core::result::Result::Ok;
use log::{debug, info, warn};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use openssl::rsa::Rsa;
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

const DEFAULT_SE_HOST_KEY_DOCUMENTS_ROOT: &str = "/run/confidential-containers/ibmse/hkds";

const DEFAULT_SE_CERTIFICATES_ROOT: &str = "/run/confidential-containers/ibmse/certs";

const DEFAULT_SE_CERTIFICATE_ROOT_CA: &str = "/run/confidential-containers/ibmse/DigiCertCA.crt";

const DEFAULT_SE_CERTIFICATE_REVOCATION_LISTS_ROOT: &str =
    "/run/confidential-containers/ibmse/crls";

const DEFAULT_SE_IMAGE_HEADER_FILE: &str = "/run/confidential-containers/ibmse/hdr/hdr.bin";

const DEFAULT_SE_MEASUREMENT_ENCR_KEY_PRIVATE: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pem";

const DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC: &str =
    "/run/confidential-containers/ibmse/rsa/encrypt_key.pub";

const DEFAULT_SE_SKIP_CERTS_VERIFICATION: &str = "false";

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
    #[serde_as(as = "Hex")]
    user_data: Vec<u8>,
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
        let private_key = Rsa::private_key_from_pem(&priv_contents)?;
        let private_key = PKey::from_rsa(private_key)?;

        let pub_key_file = env_or_default!(
            "SE_MEASUREMENT_ENCR_KEY_PUBLIC",
            DEFAULT_SE_MEASUREMENT_ENCR_KEY_PUBLIC
        );
        let pub_contents = fs::read(pub_key_file)?;
        let rsa = Rsa::public_key_from_pem(&pub_contents)?;
        let public_key = PKey::from_rsa(rsa)?;

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

    pub fn evaluate(&self, evidence: &[u8]) -> Result<TeeEvidenceParsedClaim> {
        info!("IBM SE verify API called.");

        // evidence is serialized SeAttestationResponse String bytes
        let se_response: SeAttestationResponse = serde_json::from_slice(evidence)?;

        let meas_key = self
            .decrypt(&se_response.encr_measurement_key)
            .context("decrypt Measurement Key")?;
        let nonce = self
            .decrypt(&se_response.encr_request_nonce)
            .context("decrypt Request Nonce")?;

        let nonce_array: [u8; 16] = nonce
            .try_into()
            .map_err(|_| anyhow!("Failed to convert nonce from Vec<u8> to [u8; 16], It must have exactly 16 elements."))?;

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
            bail!("Failed to verify the measurement!");
        }

        let mut att_flags = AttestationFlags::default();
        att_flags.set_image_phkh();
        att_flags.set_attest_phkh();
        let add_data = AdditionalData::from_slice(&se_response.additional_data, &att_flags)?;
        debug!("additional_data: {:?}", add_data);
        let image_phkh = add_data
            .image_public_host_key_hash()
            .ok_or(anyhow!("Failed to get image_public_host_key_hash."))?;
        let attestation_phkh = add_data
            .attestation_public_host_key_hash()
            .ok_or(anyhow!("Failed to get attestation_public_host_key_hash."))?;

        let claims = SeAttestationClaims {
            cuid: se_response.cuid,
            user_data: se_response.user_data.clone(),
            version: AttestationVersion::One as u32,
            image_phkh: image_phkh.to_vec(),
            attestation_phkh: attestation_phkh.to_vec(),
            tag: *se_response.image_hdr_tags.tag(),
        };

        serde_json::to_value(claims).context("build json value from the se claims")
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
        let skip_certs_env = env_or_default!(
            "SE_SKIP_CERTS_VERIFICATION",
            DEFAULT_SE_SKIP_CERTS_VERIFICATION
        );
        let skip_certs: bool = skip_certs_env.parse::<bool>().unwrap_or(false);
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
            if skip_certs {
                warn!("SE_SKIP_CERTS_VERIFICATION set '{skip_certs}' never use it in production!")
            } else {
                let verifier = CertVerifier::new(ca_certs.as_slice(), crls.as_slice(), Some(root_ca_path.clone()), false)?;
                verifier.verify(c)?;
            }
            arcb.add_hostkey(c.public_key()?);
        }

        let encr_ctx = ReqEncrCtx::random(SymKeyType::Aes256)?;
        let request_blob = arcb.encrypt(&encr_ctx)?;
        let conf_data = arcb.confidential_data();
        let encr_measurement_key =
            self.encrypt(conf_data.measurement_key())?;
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
        };

        let challenge = serde_json::to_string(&se_attestation_request)?;
        Ok(challenge)
    }
}
