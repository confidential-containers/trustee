// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use chrono::{DateTime, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use tracing::{trace, warn};

use crate::nvidia::NrasJwks;

/// Nested certificate-chain claims shared by GPU / nvSwitch Claims v3.0
/// `x-nvidia-*-cert-chain` fields.
///
/// <https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html>
/// <https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/nvswitch_claims.html>
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NrasGpuCertChainClaims {
    /// Certificate expiration date in ISO 8601 format.
    x_nvidia_cert_expiration_date: Option<String>,

    /// Certificate status: `valid`, `expired`, `invalid`, or `revoked`.
    x_nvidia_cert_status: Option<String>,

    /// OCSP status: `good`, `revoked`, or `unknown`.
    x_nvidia_cert_ocsp_status: Option<String>,

    /// Whether the OCSP response nonce matches the request nonce for all
    /// certificates in the chain (freshness / anti-replay).
    x_nvidia_cert_ocsp_nonce_matches: Option<bool>,

    /// Whether the OCSP response is cryptographically valid and the responder
    /// is trusted for all certificates in the chain.
    x_nvidia_cert_ocsp_response_valid: Option<bool>,

    /// Revocation reason when the certificate status is `revoked`.
    x_nvidia_cert_revocation_reason: Option<String>,
}

impl NrasGpuCertChainClaims {
    /// Verify nested cert-chain fields.
    ///
    /// If `strict` is true, missing fields are treated as errors.
    /// If `strict` is false, missing fields are treated as warnings.
    fn verify(&self, claim_name: &str, strict: bool) -> Result<()> {
        match &self.x_nvidia_cert_ocsp_status {
            Some(status) if status == "good" => {}
            Some(status) => {
                if strict {
                    if let Some(reason) = &self.x_nvidia_cert_revocation_reason {
                        warn!("x-nvidia-cert-ocsp-status reason \"{reason}\"");
                    }
                    bail!("{claim_name}.x-nvidia-cert-ocsp-status expected \"good\", got \"{status}\"")
                } else {
                    trace!("{claim_name}.x-nvidia-cert-ocsp-status expected \"good\", got \"{status}\"");
                }
            }
            None if strict => bail!("{claim_name}.x-nvidia-cert-ocsp-status is missing"),
            None => trace!("{claim_name}.x-nvidia-cert-ocsp-status is missing"),
        }

        match &self.x_nvidia_cert_status {
            Some(status) if status == "valid" => {}
            Some(status) => {
                if strict {
                    bail!("{claim_name}.x-nvidia-cert-status expected \"valid\", got \"{status}\"")
                } else {
                    trace!(
                        "{claim_name}.x-nvidia-cert-status expected \"valid\", got \"{status}\""
                    );
                }
            }
            None if strict => bail!("{claim_name}.x-nvidia-cert-status is missing"),
            None => trace!("{claim_name}.x-nvidia-cert-status is missing"),
        }

        match self.x_nvidia_cert_ocsp_nonce_matches {
            Some(true) => {}
            Some(false) => {
                if strict {
                    bail!("{claim_name}.x-nvidia-cert-ocsp-nonce-matches check failed")
                } else {
                    trace!("{claim_name}.x-nvidia-cert-ocsp-nonce-matches check failed");
                }
            }
            None if strict => bail!("{claim_name}.x-nvidia-cert-ocsp-nonce-matches is missing"),
            None => trace!("{claim_name}.x-nvidia-cert-ocsp-nonce-matches is missing"),
        }

        match self.x_nvidia_cert_ocsp_response_valid {
            Some(true) => {}
            Some(false) => {
                if strict {
                    bail!("{claim_name}.x-nvidia-cert-ocsp-response-valid check failed")
                } else {
                    trace!("{claim_name}.x-nvidia-cert-ocsp-response-valid check failed");
                }
            }
            None if strict => bail!("{claim_name}.x-nvidia-cert-ocsp-response-valid is missing"),
            None => trace!("{claim_name}.x-nvidia-cert-ocsp-response-valid is missing"),
        }

        match &self.x_nvidia_cert_expiration_date {
            Some(expiration_date) => {
                let date = DateTime::parse_from_rfc3339(expiration_date)
                    .context("invalid expiration date")?;
                if date < Utc::now() {
                    bail!("{claim_name}.x-nvidia-cert-expiration-date is in the past")
                } else {
                    trace!("{claim_name}.x-nvidia-cert-expiration-date is in the past");
                }
            }
            None if strict => bail!("{claim_name}.x-nvidia-cert-expiration-date is missing"),
            None => trace!("{claim_name}.x-nvidia-cert-expiration-date is missing"),
        }

        Ok(())
    }
}

/// Detached individual GPU claims from NRAS EAT (GPU Claims v3.0).
///
/// <https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html>
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NrasIndividualClaims {
    /// Driver RIM conforms to the SWID schema.
    x_nvidia_gpu_driver_rim_schema_validated: Option<bool>,

    /// vBIOS RIM certificate chain status (expiration, OCSP, revocation).
    x_nvidia_gpu_vbios_rim_cert_chain: Option<NrasGpuCertChainClaims>,

    /// Attestation report certificate chain status (expiration, OCSP, revocation).
    x_nvidia_gpu_attestation_report_cert_chain: Option<NrasGpuCertChainClaims>,

    /// FWID of the certificate matches the attestation report.
    x_nvidia_gpu_attestation_report_cert_chain_fwid_match: Option<bool>,

    /// Attestation report was successfully parsed.
    x_nvidia_gpu_attestation_report_parsed: Option<bool>,

    /// Driver RIM signature is verified.
    x_nvidia_gpu_driver_rim_signature_verified: Option<bool>,

    /// VBIOS RIM signature is verified.
    x_nvidia_gpu_vbios_rim_signature_verified: Option<bool>,

    /// GPU architecture in the attestation report is Ampere or Hopper.
    x_nvidia_gpu_arch_check: Option<bool>,

    /// Warning populated when a certificate is revoked with reason `CERT_HOLD`.
    #[serde(rename = "x-nvidia-attestation-warning")]
    _x_nvidia_attestation_warning: Option<bool>,

    /// Attestation report signature is verified.
    x_nvidia_gpu_attestation_report_signature_verified: Option<bool>,

    /// vBIOS RIM conforms to the SWID schema.
    x_nvidia_gpu_vbios_rim_schema_validated: Option<bool>,

    /// Driver RIM certificate chain status (expiration, OCSP, revocation).
    x_nvidia_gpu_driver_rim_cert_chain: Option<NrasGpuCertChainClaims>,

    /// VBIOS RIM and its measurements were successfully interpreted.
    x_nvidia_gpu_vbios_rim_measurements_available: Option<bool>,

    /// Driver RIM and its measurements were successfully interpreted.
    x_nvidia_gpu_driver_rim_measurements_available: Option<bool>,

    /// GPU driver version (e.g. `550.90.07`).
    pub(crate) x_nvidia_gpu_driver_version: Option<String>,

    /// GPU vBIOS version (e.g. `96.00.9F.00.01`).
    pub(crate) x_nvidia_gpu_vbios_version: Option<String>,

    /// Runtime measurements from RIM match the attestation report (`success` / `fail`).
    measres: Option<String>,

    /// Nonce in the attestation report matches the nonce used to generate it.
    x_nvidia_gpu_attestation_report_nonce_match: Option<bool>,

    /// Driver RIM was fetched from the RIM service.
    x_nvidia_gpu_driver_rim_fetched: Option<bool>,

    /// vBIOS RIM was fetched from the RIM service.
    x_nvidia_gpu_vbios_rim_fetched: Option<bool>,

    /// Driver and vBIOS RIM files do not have active measurements at the same index.
    x_nvidia_gpu_vbios_index_no_conflict: Option<bool>,

    /// Driver RIM file version matches the version from GPU information.
    x_nvidia_gpu_driver_rim_version_match: Option<bool>,

    /// vBIOS RIM file version matches the version from GPU information.
    x_nvidia_gpu_vbios_rim_version_match: Option<bool>,

    /// Nonce used for the attestation process.
    #[serde(rename = "eat_nonce")]
    pub(crate) eat_nonce: Option<String>,

    /// GPU hardware model.
    pub(crate) hwmodel: Option<String>,

    /// Universal Entity Id.
    pub(crate) ueid: Option<String>,

    /// Firmware manufacturer id.
    pub(crate) oemid: Option<String>,

    /// EAT token issuer.
    pub(crate) iss: Option<String>,

    /// Whether Secure Boot is enabled.
    pub(crate) secboot: Option<bool>,

    /// Whether GPU debug facilities are enabled (`enabled` / `disabled`).
    pub(crate) dbgstat: Option<String>,

    /// Unique physical data interfaces from GPUs to NVSwitches (optional).
    pub(crate) x_nvidia_gpu_switch_pdis: Option<Vec<String>>,
}

impl NrasIndividualClaims {
    /// Verify individual GPU claims following the rules:
    ///
    /// - GPU evidence endorsements / report data nonce match and arch check are enforced.
    /// - Other parts are optional based on the debug mode.
    pub fn verify(&self, debug: bool) -> Result<()> {
        // Firstly, check the gpu evidence endorsement, report data nonce match, and arch check.
        // This check is enforced.
        check_true(
            "x-nvidia-gpu-attestation-report-parsed",
            &self.x_nvidia_gpu_attestation_report_parsed,
            true,
        )?;
        check_true(
            "x-nvidia-gpu-attestation-report-signature-verified",
            &self.x_nvidia_gpu_attestation_report_signature_verified,
            true,
        )?;
        check_cert_chain(
            "x-nvidia-gpu-attestation-report-cert-chain",
            &self.x_nvidia_gpu_attestation_report_cert_chain,
            true,
        )?;
        check_true(
            "x-nvidia-gpu-attestation-report-cert-chain-fwid-match",
            &self.x_nvidia_gpu_attestation_report_cert_chain_fwid_match,
            true,
        )?;

        check_true(
            "x-nvidia-gpu-attestation-report-nonce-match",
            &self.x_nvidia_gpu_attestation_report_nonce_match,
            true,
        )?;

        check_true(
            "x-nvidia-gpu-arch-check",
            &self.x_nvidia_gpu_arch_check,
            true,
        )?;

        // If it's not debug mode, secboot must be true and dbgstat must be "disabled".
        check_true("secboot", &self.secboot, !debug)?;
        check_str_eq("dbgstat", &self.dbgstat, "disabled", !debug)?;

        // If it's not debug mode, the GPU driver must be present and verified.
        check_true(
            "x-nvidia-gpu-driver-rim-fetched",
            &self.x_nvidia_gpu_driver_rim_fetched,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-driver-rim-schema-validated",
            &self.x_nvidia_gpu_driver_rim_schema_validated,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-driver-rim-signature-verified",
            &self.x_nvidia_gpu_driver_rim_signature_verified,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-driver-rim-measurements-available",
            &self.x_nvidia_gpu_driver_rim_measurements_available,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-driver-rim-version-match",
            &self.x_nvidia_gpu_driver_rim_version_match,
            !debug,
        )?;
        check_cert_chain(
            "x-nvidia-gpu-driver-rim-cert-chain",
            &self.x_nvidia_gpu_driver_rim_cert_chain,
            !debug,
        )?;

        // Then, check the vBIOS RIM.
        check_true(
            "x-nvidia-gpu-vbios-rim-fetched",
            &self.x_nvidia_gpu_vbios_rim_fetched,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-vbios-rim-schema-validated",
            &self.x_nvidia_gpu_vbios_rim_schema_validated,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-vbios-rim-signature-verified",
            &self.x_nvidia_gpu_vbios_rim_signature_verified,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-vbios-rim-version-match",
            &self.x_nvidia_gpu_vbios_rim_version_match,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-vbios-rim-measurements-available",
            &self.x_nvidia_gpu_vbios_rim_measurements_available,
            !debug,
        )?;
        check_cert_chain(
            "x-nvidia-gpu-vbios-rim-cert-chain",
            &self.x_nvidia_gpu_vbios_rim_cert_chain,
            !debug,
        )?;
        check_true(
            "x-nvidia-gpu-vbios-index-no-conflict",
            &self.x_nvidia_gpu_vbios_index_no_conflict,
            !debug,
        )?;

        // Then, check the GPU runtime measurements.
        check_str_eq("measres", &self.measres, "success", !debug)?;

        Ok(())
    }
}

/// Detached individual nvSwitch claims from NRAS EAT (nvSwitch Claims v3.0).
///
/// <https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/nvswitch_claims.html>
#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct NrasSwitchIndividualClaims {
    /// Switch architecture in the attestation report (e.g. `LS10`).
    x_nvidia_switch_arch_check: Option<String>,

    /// Runtime measurements from RIM match the attestation report (`success` / `fail`).
    measres: Option<String>,

    /// Switch BIOS version (e.g. `96.00.9F.00.01`).
    pub(crate) x_nvidia_switch_bios_version: Option<String>,

    /// Attestation report certificate chain status (expiration, OCSP, revocation).
    x_nvidia_switch_attestation_report_cert_chain: Option<NrasGpuCertChainClaims>,

    /// FWID of the certificate matches the attestation report.
    x_nvidia_switch_attestation_report_cert_chain_fwid_match: Option<bool>,

    /// BIOS RIM certificate chain status (expiration, OCSP, revocation).
    x_nvidia_switch_bios_rim_cert_chain: Option<NrasGpuCertChainClaims>,

    /// BIOS RIM file version matches the version from switch information.
    x_nvidia_switch_bios_rim_version_match: Option<bool>,

    /// Attestation report was successfully parsed.
    x_nvidia_switch_attestation_report_parsed: Option<bool>,

    /// Nonce in the attestation report matches the nonce used to generate it.
    x_nvidia_switch_attestation_report_nonce_match: Option<bool>,

    /// Attestation report signature is verified.
    x_nvidia_switch_attestation_report_signature_verified: Option<bool>,

    /// BIOS RIM was fetched from the RIM service.
    x_nvidia_switch_bios_rim_fetched: Option<bool>,

    /// BIOS RIM conforms to the SWID schema.
    x_nvidia_switch_bios_rim_schema_validated: Option<bool>,

    /// BIOS RIM signature is verified.
    x_nvidia_switch_bios_rim_signature_verified: Option<bool>,

    /// BIOS RIM and its measurements were successfully interpreted.
    x_nvidia_switch_bios_rim_measurements_available: Option<bool>,

    /// Nonce used for the attestation process.
    #[serde(rename = "eat_nonce")]
    pub(crate) eat_nonce: Option<String>,

    /// Switch hardware model.
    pub(crate) hwmodel: Option<String>,

    /// Universal Entity Id.
    pub(crate) ueid: Option<String>,

    /// Firmware manufacturer id.
    pub(crate) oemid: Option<String>,

    /// EAT token issuer.
    pub(crate) iss: Option<String>,

    /// NVSwitch physical data interface ID (optional).
    pub(crate) x_nvidia_switch_pdi: Option<String>,

    /// Unique physical data interfaces from NVSwitches to GPUs (optional).
    pub(crate) x_nvidia_switch_gpu_pdis: Option<Vec<String>>,

    /// Whether Secure Boot is enabled.
    pub(crate) secboot: Option<bool>,

    /// Whether NVSwitch debug facilities are enabled (`enabled` / `disabled`).
    pub(crate) dbgstat: Option<String>,
}

impl NrasSwitchIndividualClaims {
    /// Verify individual nvSwitch claims following the rules:
    ///
    /// - Attestation report endorsements / report data nonce matchare enforced.
    /// - Other parts are optional based on the debug mode.
    pub fn verify(&self, debug: bool) -> Result<()> {
        // Firstly, check the attestation report certificate chain.
        check_cert_chain(
            "x-nvidia-switch-attestation-report-cert-chain",
            &self.x_nvidia_switch_attestation_report_cert_chain,
            true,
        )?;
        check_true(
            "x-nvidia-switch-attestation-report-cert-chain-fwid-match",
            &self.x_nvidia_switch_attestation_report_cert_chain_fwid_match,
            true,
        )?;
        check_true(
            "x-nvidia-switch-attestation-report-parsed",
            &self.x_nvidia_switch_attestation_report_parsed,
            true,
        )?;
        check_true(
            "x-nvidia-switch-attestation-report-signature-verified",
            &self.x_nvidia_switch_attestation_report_signature_verified,
            true,
        )?;

        // Then, check the report data nonce match
        check_true(
            "x-nvidia-switch-attestation-report-nonce-match",
            &self.x_nvidia_switch_attestation_report_nonce_match,
            true,
        )?;

        // Then, check the secure boot and debug status based on debug flag.
        check_true("secboot", &self.secboot, !debug)?;
        check_str_eq("dbgstat", &self.dbgstat, "disabled", !debug)?;

        // Then, check switch bios based on debug flag.
        check_true(
            "x-nvidia-switch-bios-rim-fetched",
            &self.x_nvidia_switch_bios_rim_fetched,
            !debug,
        )?;
        check_true(
            "x-nvidia-switch-bios-rim-schema-validated",
            &self.x_nvidia_switch_bios_rim_schema_validated,
            !debug,
        )?;
        check_true(
            "x-nvidia-switch-bios-rim-signature-verified",
            &self.x_nvidia_switch_bios_rim_signature_verified,
            !debug,
        )?;
        check_true(
            "x-nvidia-switch-bios-rim-version-match",
            &self.x_nvidia_switch_bios_rim_version_match,
            !debug,
        )?;
        check_true(
            "x-nvidia-switch-bios-rim-measurements-available",
            &self.x_nvidia_switch_bios_rim_measurements_available,
            !debug,
        )?;
        check_cert_chain(
            "x-nvidia-switch-bios-rim-cert-chain",
            &self.x_nvidia_switch_bios_rim_cert_chain,
            !debug,
        )?;

        // v3.0 documents this as a string (e.g. LS10), not a boolean.
        match &self.x_nvidia_switch_arch_check {
            Some(arch) if !arch.is_empty() && !debug => {}
            Some(_) if debug => {}
            Some(_) => bail!("x-nvidia-switch-arch-check is empty"),
            None => trace!("x-nvidia-switch-arch-check is missing"),
        }

        // check the runtime measurements
        check_str_eq("measres", &self.measres, "success", !debug)?;

        Ok(())
    }
}

fn check_cert_chain(
    name: &str,
    chain: &Option<NrasGpuCertChainClaims>,
    strict: bool,
) -> Result<()> {
    match chain {
        Some(claims) => claims.verify(name, strict),
        None if strict => bail!("{name} is missing"),
        None => Ok(()),
    }
}

fn check_true(name: &str, value: &Option<bool>, strict: bool) -> Result<()> {
    match value {
        Some(true) => Ok(()),
        Some(false) if strict => bail!("{name} check failed"),
        Some(false) => {
            trace!("{name} check failed");
            Ok(())
        }
        None if strict => bail!("{name} is missing"),
        None => Ok(()),
    }
}

fn check_str_eq(name: &str, value: &Option<String>, expected: &str, strict: bool) -> Result<()> {
    match value {
        Some(v) if v == expected => Ok(()),
        Some(v) if strict => bail!("{name} expected \"{expected}\", got \"{v}\""),
        Some(v) => {
            trace!("{name} expected \"{expected}\", got \"{v}\"");
            Ok(())
        }
        None if strict => bail!("{name} is missing"),
        None => {
            trace!("{name} is missing");
            Ok(())
        }
    }
}

/// Internal struct for deserializing the NRAS Payload
/// The first element is a slice with two fields:
/// - The first field is "JWT" string
/// - The second field is the base64 encoded primary JWT
///
/// The second element is a HashMap with the device name as the
///   key and base64 encoded Individual JWTs as the value.
///
/// See the following link for more details
/// https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/introduction.html
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
struct NrasResponseInternal(Vec<String>, HashMap<String, String>);

/// Formatted Nras Response
pub struct NrasResponse {
    primary_token: String,
    individual_token: String,
}

impl FromStr for NrasResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let response: NrasResponseInternal = serde_json::from_str(s)?;

        if response.0.len() != 2 {
            bail!("Unexpected Payload Format");
        };
        let primary_token = response.0[1].clone();

        // For now, there should only be one EAT.
        if response.1.len() != 1 {
            bail!("Unexpected submod count.");
        };

        let individual_token = response
            .1
            .values()
            .next()
            .ok_or_else(|| anyhow!("Could not find EAT"))?
            .to_string();

        Ok(NrasResponse {
            primary_token,
            individual_token,
        })
    }
}

impl NrasResponse {
    /// Validates JWT and EAT using the provided JWKs
    pub fn validate(&self, jwks: &NrasJwks) -> Result<()> {
        validate_jwt(&self.primary_token, jwks)?;
        validate_jwt(&self.individual_token, jwks)?;

        Ok(())
    }

    /// Extracts GPU TCB Claims from individual token
    pub fn gpu_claims(&self) -> Result<NrasIndividualClaims> {
        // we just check the primary token to make sure it's valid
        let _ = get_jwt_payload::<Value>(&self.primary_token)?;
        let individual_claims = get_jwt_payload::<NrasIndividualClaims>(&self.individual_token)?;

        Ok(individual_claims)
    }

    /// Extracts nvSwitch TCB Claims from individual token
    pub fn switch_claims(&self) -> Result<NrasSwitchIndividualClaims> {
        let _ = get_jwt_payload::<Value>(&self.primary_token)?;
        let individual_claims =
            get_jwt_payload::<NrasSwitchIndividualClaims>(&self.individual_token)?;

        Ok(individual_claims)
    }
}

pub fn get_jwt_payload<T: DeserializeOwned>(jwt: &str) -> Result<T> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        bail!("Malformed JWT");
    }

    let b64_engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let payload_bytes = b64_engine.decode(parts[1])?;
    let payload_str = String::from_utf8_lossy(&payload_bytes);

    Ok(serde_json::from_str(&payload_str)?)
}

pub fn get_jwt_kid(jwt: &str) -> Result<String> {
    let header = jsonwebtoken::decode_header(jwt)?;
    let kid = header.kid.ok_or_else(|| anyhow!("Could not find KID"))?;

    Ok(kid)
}

pub fn validate_jwt(jwt: &str, jwks: &NrasJwks) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        exp: usize,
        iat: usize,
        iss: String,
        nbf: usize,
    }

    let kid = get_jwt_kid(jwt)?;
    let jwk = jwks
        .get(kid)
        .ok_or_else(|| anyhow!("Could not find KID in JWKs"))?;

    let decoding_key = DecodingKey::from_jwk(&jwk)?;

    decode::<Claims>(jwt, &decoding_key, &Validation::new(Algorithm::ES384))?;

    Ok(())
}
