// Copyright (c) 2025 by Red Hat.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::attestation::backend::{Attest, IndependentEvidence};
use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use derivative::Derivative;
use jsonwebtoken::{
    jwk::{AlgorithmParameters, CommonParameters, Jwk, KeyAlgorithm, RSAKeyParameters, RSAKeyType},
    Algorithm, EncodingKey, Header,
};
use kbs_types::{RuntimeData, Tee, TeePubKey};
use openssl::{pkey::Public, rsa::Rsa};
use reqwest::{
    header::CONTENT_TYPE,
    tls::{Certificate, Identity},
    Client, ClientBuilder,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Number, Value};
use std::fs;
use time::{Duration, OffsetDateTime};

/// Configuration of the Keylime verifier.
#[derive(Clone, Debug, Derivative, Deserialize, PartialEq, Default)]
pub struct KeylimeVerifierConfig {
    /// Base URL of the verifier.
    pub base_url: String,
    /// API version (i.e. verifier version {MAJOR}.{MINOR}).
    pub api_version_major: u8,
    pub api_version_minor: u8,
    /// Path of the verifier CA certificates.
    pub cv_ca_path: String,
}

/// Configuration of the KBS frontend for the Keylime verifier.
pub struct KeylimeTeeHandler {
    /// Verifier config.
    config: KeylimeVerifierConfig,
    /// HTTP client to communicate with the verifier.
    client: Client,
    /// Verifier private key, used to sign JWTs on behalf of verifier.
    priv_key: EncodingKey,
    /// Verifier public key, used to verify JWT signatures on behalf of verifier.
    pub_key: Rsa<Public>,
}

/// HTTP response status.
#[derive(Debug, Deserialize)]
enum KeylimeAttestationStatus {
    #[serde(rename = "Success")]
    Success,

    #[serde(rename = "Internal Server Error")]
    InternalServerError,

    #[serde(rename = "Internal Server Error: Failed to process attestation data")]
    FailedAttestationDataProcess,
}

/// JSON response from Keylime /verify/evidence API.
#[derive(Debug, Deserialize)]
struct KeylimeTeeResponse {
    /// HTTP response status codes.
    #[serde(rename = "code")]
    _code: usize,
    /// HTTP response status.
    status: KeylimeAttestationStatus,
    /// Attestation results.
    results: KeylimeTeeResults,
}

/// Keylime /verify/evidence attestation results.
#[derive(Debug, Deserialize)]
struct KeylimeTeeResults {
    /// Indicates if attestation was successful.
    valid: bool,
    /// Failure reasons. May be empty if attestation is successful.
    failures: Vec<Value>,
    /// Evidence claims. May be empty if attestation is unsuccessful.
    claims: Map<String, Value>,
}

/// Attestation failure reason object.
#[derive(Debug, Deserialize)]
struct KeylimeTeeFailureReason {
    /// Type of failure, encoded by Keylime verifier.
    #[serde(rename = "type")]
    _err_type: KeylimeTeeErrorType,
    /// Error message.
    #[serde(rename = "message")]
    _message: String,
}

/// Keylime verifier TEE attestation error types.
#[derive(Debug, Deserialize)]
enum KeylimeTeeErrorType {
    #[serde(rename = "tee_attestation.freshness_hash_failed")]
    FreshnessHash,
    #[serde(rename = "tee_attestation.invalid_signature")]
    InvalidSignature,
    #[serde(rename = "tee_attestation.vcek_fetch")]
    SevSnpVcekFetch,
    #[serde(rename = "tee_attestation.invalid_public_key")]
    SevSnpInvalidPublicKey,
}

#[async_trait]
impl Attest for KeylimeTeeHandler {
    async fn verify(&self, evidence_to_verify: Vec<IndependentEvidence>) -> Result<String> {
        let tee_data = TeeData::try_from(evidence_to_verify)
            .context("unable to deserialize independent evidence to Keylime TEE data")?;

        log::debug!("Keylime TEE data: {:#?}", tee_data);

        let req = json!({
            "type": "tee".to_string(),
            "data": &tee_data.req,
        });

        // Send the evidence and receive a response back from the verifier.
        let resp = self
            .client
            .post(format!(
                "{}/v{}.{}/verify/evidence",
                self.config.base_url, self.config.api_version_major, self.config.api_version_minor
            ))
            .header(CONTENT_TYPE, "application/json")
            .json(&req)
            .send()
            .await
            .context("Failed to POST attestation HTTP request")?;

        let mut response: KeylimeTeeResponse = {
            let resp_text = resp
                .text()
                .await
                .context("unable to fetch response text from /verify/evidence endpoint")?;

            serde_json::from_str(&resp_text)
                .context("unable to deserialize keylime /verify/evidence results")?
        };

        log::debug!("keylime response: {:#?}", response);

        // Handle the verifier's attestation response based on the attestation's result.
        match response.status {
            KeylimeAttestationStatus::Success => {
                if response.results.valid {
                    // TEE attestation succeeded. Construct a JWT with the claims from the verifier
                    // and sign it with Keylime's private key.
                    self.make_jwt(
                        &mut response.results.claims,
                        BASE64_STANDARD
                            .decode(tee_data.req.nonce)
                            .context("unable to decode runtime nonce from base64")?,
                        tee_data.pubkey,
                    )
                } else {
                    // TEE attestation failed, return the reasons for failure to the client.
                    bail!("client attestation failed: {:?}", response.results.failures);
                }
            }
            KeylimeAttestationStatus::InternalServerError => {
                Err(anyhow!("Keylime internal server error"))
            }
            KeylimeAttestationStatus::FailedAttestationDataProcess => Err(anyhow!(
                "Keylime internal server error: Failed to process attestation data"
            )),
        }
    }
}

impl KeylimeTeeHandler {
    /// Configure the KBS frontend for the Keylime verifier. Keylime requires mTLS for all
    /// commmunication, so it is assumed that the KBS has access to the certificates needed to
    /// establish its identity for mTLS. The KBS also signs and validates JWTs on behalf of the
    /// verifier (that is, using the verifier's private/public keys). With that, it is assumed that
    /// the KBS also has access to the server's keypair.
    pub async fn new(config: KeylimeVerifierConfig) -> Result<Self> {
        // Retrieve the verifier's CA certificate.
        let ca_cert = {
            let path = format!("{}/cacert.crt", config.cv_ca_path);
            let x509_pem = fs::read(&path).context(format!(
                "unable to read Keylime CA certificate file from {}",
                path
            ))?;

            Certificate::from_pem(&x509_pem).context(
                format!(
                    "bytes in Keylime verifier CA certificate file ({}) not a valid PEM-encoded X509 certificate",
                    path
                )
            )?
        };

        // Build the TLS identity from client ceritifcate and private key.
        let tls_identity = {
            let mut vec = vec![];

            // Retrieve the verifier's client X509 certificate.
            let cli_cert = {
                let path = format!("{}/client-cert.crt", config.cv_ca_path);

                fs::read(&path).context(format!(
                    "unable to read Keylime client X509 certificate file from {}",
                    path
                ))?
            };

            vec.extend_from_slice(&cli_cert);

            // Retrieve the verifier's client private key.
            let cli_priv_key = {
                let path = format!("{}/client-private.pem", config.cv_ca_path);

                fs::read(&path).context(format!(
                    "unable to read Keylime client private key file from {}",
                    path
                ))?
            };

            vec.extend_from_slice(&cli_priv_key);

            vec
        };

        // Retrieve the verifier's server public key.
        let pub_key = {
            let path = format!("{}/server-public.pem", config.cv_ca_path);

            let pem = fs::read(&path).context(format!(
                "unable to read Keylime server public key file from {}",
                path
            ))?;

            Rsa::public_key_from_pem(&pem).context("unable to decode RSA server public key")?
        };

        // Retrieve the verifier's server private key.
        let priv_key = {
            let path = format!("{}/server-private.pem", config.cv_ca_path);

            let pem = fs::read(&path).context(format!(
                "unable to read Keylime server private key file from {}",
                path
            ))?;

            EncodingKey::from_rsa_pem(&pem)
                .context("unable to create JWT encoding key from Keylime Verifier private key")?
        };

        // Build an HTTP client to communicate with the Keylime verifier. Establish an identity
        // using the verifier's certificates.
        let client = ClientBuilder::new()
            .identity(
                Identity::from_pem(tls_identity.as_slice())
                    .context("unable to establish client certificate authentication identity")?,
            )
            .add_root_certificate(ca_cert)
            .danger_accept_invalid_certs(true)
            .build()
            .context("unable to build HTTP client to Keylime verifier")?;

        Ok(Self {
            config: config.clone(),
            client,
            priv_key,
            pub_key,
        })
    }

    /// Marshal a JSON Web Token containing the claims attested for a specific client by the
    /// Keylime verifier. Sign the JWT with the verifier's private key to establish authenticity.
    fn make_jwt(
        &self,
        claims: &mut Map<String, Value>,
        nonce: Vec<u8>,
        tee_pubkey: TeePubKey,
    ) -> Result<String> {
        let mut jwt_claims: Map<String, Value> = Map::new();
        let exp = {
            let now = OffsetDateTime::now_utc();

            now.checked_add(Duration::minutes(5))
                .context("unable to calculate token expiration")
        }?;

        jwt_claims.insert(
            "exp".to_string(),
            Value::Number(
                Number::from_i128(exp.unix_timestamp().into())
                    .context("unable to set expiration unix timestamp")?,
            ),
        );

        jwt_claims.insert(
            "nonce".to_string(),
            serde_json::to_value(nonce).context("unable to serialize nonce to JSON value")?,
        );

        jwt_claims.insert(
            "tee-pubkey".to_string(),
            serde_json::to_value(tee_pubkey)
                .context("unable to serialize TEE public key to JSON value")?,
        );

        jwt_claims.insert(
            "tee-claims".to_string(),
            serde_json::to_value(claims)
                .context("unable to serialize TEE claims map to JSON value")?,
        );

        let header = Header {
            alg: Algorithm::RS256,
            jwk: Some(Jwk {
                common: CommonParameters {
                    key_algorithm: Some(KeyAlgorithm::RS256),
                    ..Default::default()
                },
                algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
                    key_type: RSAKeyType::RSA,
                    n: BASE64_URL_SAFE_NO_PAD.encode(self.pub_key.n().to_vec()),
                    e: BASE64_URL_SAFE_NO_PAD.encode(self.pub_key.e().to_vec()),
                }),
            }),
            ..Default::default()
        };

        let token = jsonwebtoken::encode(&header, &jwt_claims, &self.priv_key)
            .context("unable to create JWT from claims")?;

        Ok(token)
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct TeeData {
    req: TeeRequest,
    pubkey: TeePubKey,
}

impl TryFrom<Vec<IndependentEvidence>> for TeeData {
    type Error = anyhow::Error;

    fn try_from(evidence_list: Vec<IndependentEvidence>) -> Result<Self, Self::Error> {
        // Only one set of TEE evidence can be verified by Keylime at the moment.
        if evidence_list.len() != 1 {
            bail!("only one TEE evidence type currently supported for keylime attestation");
        }

        let data = &evidence_list[0];

        match data.tee {
            Tee::Snp => (),
            _ => bail!("invalid TEE"),
        }

        // Get the TEE architecture evidence and runtime data.
        let tee_arch_evidence: TeeArchitectureEvidence =
            serde_json::from_value(data.tee_evidence.clone())
                .context("unable to deserialize independent TEE evidence")?;
        let runtime: RuntimeData = serde_json::from_value(data.runtime_data.clone())
            .context("unable to deserialize independent runtime data")?;

        let tee_pubkey = runtime.tee_pubkey;

        // Only EC keys are permitted as the TEE public key.
        let TeePubKey::EC {
            crv: _,
            alg: _,
            x,
            y,
        } = tee_pubkey.clone()
        else {
            bail!("TEE public key must be elliptic curve key");
        };

        // Build a request to specify the type of TEE and its respective evidence for the Keylime
        // /verify/evidence TEE handler.
        let req = TeeRequest {
            tee_evidence: TeeEvidence::from(tee_arch_evidence),
            nonce: runtime.nonce,
            x,
            y,
        };

        Ok(Self {
            req,
            pubkey: tee_pubkey,
        })
    }
}

/// A /verify/evidence TEE attestation request to the Keylime verifier.
#[derive(Debug, Deserialize, Serialize)]
struct TeeRequest {
    /// The TEE evidence (also containing the TEE architecture in which to deserialize the evidence
    /// as).
    #[serde(rename = "tee-evidence")]
    tee_evidence: TeeEvidence,
    /// The nonce produced by the KBS challenge.
    nonce: String,
    /// TEE public key x coordinate.
    #[serde(rename = "tee-pubkey-x-b64")]
    x: String,
    /// TEE public key y coordinate.
    #[serde(rename = "tee-pubkey-y-b64")]
    y: String,
}

/// Evidence formatting based on TEE architecture.
#[derive(Debug, Deserialize, Serialize)]
struct TeeEvidence {
    /// TEE architecture.
    tee: Tee,
    /// Attestation evidence.
    evidence: TeeArchitectureEvidence,
}

impl From<TeeArchitectureEvidence> for TeeEvidence {
    fn from(evidence: TeeArchitectureEvidence) -> Self {
        let tee: Tee = (&evidence).into();

        Self { tee, evidence }
    }
}

/// Evidence formatting based on TEE architecture. Enum is untagged due to the underyling data
/// being parsed based off the Evidence's `tee` member.
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum TeeArchitectureEvidence {
    /// SEV-SNP evidence.
    Snp {
        /// SEV-SNP attestation report.
        #[serde(rename = "snp-report")]
        snp_report: String,
        /// Optional ceritficate buffer from hypervisor.
        #[serde(rename = "certs-buf")]
        certs_buf: Option<String>,
    },
}

impl From<&TeeArchitectureEvidence> for Tee {
    fn from(evidence: &TeeArchitectureEvidence) -> Self {
        match evidence {
            TeeArchitectureEvidence::Snp { .. } => Tee::Snp,
        }
    }
}
