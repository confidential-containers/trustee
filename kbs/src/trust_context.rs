// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use kbs_types::TeePubKey;
use openssl::{
    pkey::{PKey, Private, Public},
    sign::{Signer, Verifier},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sigstore_types::{DsseEnvelope, DsseSignature, KeyId, PayloadBytes, SignatureBytes};
use tracing::warn;

pub const TRUST_CONTEXT_PAYLOAD_TYPE: &str =
    "https://github.com/confidential-containers/kbs/trust-context";

/// Trust Context is an overall abstraction upon different backend
/// attestation services. This will help the KBS to keep only one
/// policy to filter different attestation results. The context
/// is a general representation of the attestation results upon a
/// given TEE env. This context is used to work as a "passport" to
/// access different KBS plugins.
#[derive(Serialize, Deserialize, Clone)]
pub struct TrustContext {
    pub attestation_summary: AttestationSummary,
    pub tee_pubkey: TeePubKey,
    pub custom_claims: Value,
}

/// The overall abstraction of the attestation result.
/// This is used to hide the different token formats of
/// backend attestation services and provide a unified interface
/// to the KBS.
///
/// TODO: add more fields to the summary, or change the existing fields.
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct AttestationSummary {
    pub allowed: bool,
}

#[derive(Serialize, Deserialize)]
pub struct SignedTrustContext(DsseEnvelope);

impl SignedTrustContext {
    pub fn new(trust_context: TrustContext, private_key: &PKey<Private>) -> Result<Self> {
        let payload = serde_json::to_vec(&trust_context)?;
        let mut signer = Signer::new_without_digest(private_key)?;
        signer.update(&payload)?;
        let sig = signer.sign_to_vec()?;
        let dsse_signature = DsseSignature {
            sig: SignatureBytes::from(sig),
            keyid: KeyId::default(),
        };
        let dsse_envelope = DsseEnvelope::new(
            TRUST_CONTEXT_PAYLOAD_TYPE.to_string(),
            PayloadBytes::from(payload),
            vec![dsse_signature],
        );
        Ok(Self(dsse_envelope))
    }

    pub fn verify(&self, public_key: &PKey<Public>) -> Result<TrustContext> {
        let payload = self.0.payload.as_bytes();
        let mut verifier = Verifier::new_without_digest(public_key)?;
        verifier.update(payload)?;
        let sig = self.0.signatures[0].sig.as_bytes();
        verifier.verify(sig)?;
        let trust_context = serde_json::from_slice(payload)?;
        Ok(trust_context)
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Default)]
pub struct TrustContextConfig {
    /// URLs (file:// and https:// schemes accepted) pointing to a public key file
    #[serde(default)]
    pub public_keys: Vec<String>,

    /// Path to the private key file.
    pub private_key: Option<String>,
}

pub struct TrustContextManager {
    public_key: Vec<PKey<Public>>,
    private_key: PKey<Private>,
}

impl TrustContextManager {
    pub fn new(config: &TrustContextConfig) -> Result<Self> {
        let (public_key, private_key) = match (config.public_keys.is_empty(), &config.private_key) {
            (false, Some(private_key)) => {
                let public_keys = config
                    .public_keys
                    .iter()
                    .map(|public_key| {
                        let public_key_pem =
                            load_public_key(public_key).context("Failed to read public key")?;
                        PKey::public_key_from_pem(&public_key_pem)
                            .context("Failed to parse public key")
                    })
                    .collect::<Result<Vec<PKey<Public>>>>()?;

                let private_key_pem =
                    std::fs::read(private_key).context("Failed to read private key")?;
                let private_key = PKey::private_key_from_pem(&private_key_pem)
                    .context("Failed to parse private key")?;
                (public_keys, private_key)
            }
            (true, None) => {
                warn!("No public or private key provided for trust context. Generate an ephemeral key pair use to sign and verify the trust context.");
                let private_key = PKey::generate_ed25519()?;
                let public_key = private_key.public_key_to_pem()?;
                let public_key =
                    PKey::public_key_from_pem(&public_key).context("Failed to parse public key")?;
                (vec![public_key], private_key)
            }
            _ => {
                bail!("Please provide either both public and private keys or neither (use an ephemeral key pair to sign and verify the trust context)")
            }
        };
        Ok(Self {
            public_key,
            private_key,
        })
    }

    pub fn sign(&self, trust_context: TrustContext) -> Result<SignedTrustContext> {
        SignedTrustContext::new(trust_context, &self.private_key)
    }

    pub fn verify(&self, signed_trust_context: SignedTrustContext) -> Result<TrustContext> {
        for public_key in &self.public_key {
            if let Ok(trust_context) = signed_trust_context.verify(public_key) {
                return Ok(trust_context);
            }
        }
        bail!("Failed to verify signed trust context with any of the public keys");
    }
}

fn load_public_key(public_uri: &str) -> Result<Vec<u8>> {
    if public_uri.starts_with("file://") {
        let public_key_pem = std::fs::read(
            public_uri
                .strip_prefix("file://")
                .context("Failed to read public key")?,
        )?;
        Ok(public_key_pem)
    } else if public_uri.starts_with("https://") {
        let public_key_pem = reqwest::blocking::get(public_uri)
            .with_context(|| format!("Failed to get public key from URL: {}", public_uri))?
            .bytes()
            .with_context(|| format!("Failed to read public key from URL: {}", public_uri))?
            .to_vec();
        Ok(public_key_pem)
    } else {
        bail!("Invalid public key URI: {}", public_uri);
    }
}
