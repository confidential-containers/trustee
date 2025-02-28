// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::{HttpRequest, HttpResponse};
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use kbs_types::{Attestation, Challenge, Request, Tee};
use lazy_static::lazy_static;
use log::{debug, info};
use rand::{thread_rng, Rng};
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use serde::Deserialize;
use serde_json::json;

use crate::attestation::session::KBS_SESSION_ID;

use super::{
    config::{AttestationConfig, AttestationServiceConfig},
    session::{SessionMap, SessionStatus},
    Error, Result,
};

static KBS_MAJOR_VERSION: u64 = 0;
static KBS_MINOR_VERSION: u64 = 2;
static KBS_PATCH_VERSION: u64 = 0;

lazy_static! {
    static ref VERSION_REQ: VersionReq = {
        let kbs_version = Version {
            major: KBS_MAJOR_VERSION,
            minor: KBS_MINOR_VERSION,
            patch: KBS_PATCH_VERSION,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };

        VersionReq::parse(&format!("={kbs_version}")).unwrap()
    };
}

/// Number of bytes in a nonce.
const NONCE_SIZE_BYTES: usize = 32;

/// Create a nonce and return as a base-64 encoded string.
pub async fn make_nonce() -> anyhow::Result<String> {
    let mut nonce: Vec<u8> = vec![0; NONCE_SIZE_BYTES];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(STANDARD.encode(&nonce))
}

pub(crate) async fn generic_generate_challenge(
    _tee: Tee,
    _tee_parameters: serde_json::Value,
) -> anyhow::Result<Challenge> {
    let nonce = make_nonce().await?;

    Ok(Challenge {
        nonce,
        extra_params: serde_json::Value::String(String::new()),
    })
}

/// Interface for Attestation Services.
///
/// Attestation Service implementations should implement this interface.
#[async_trait]
pub trait Attest: Send + Sync {
    /// Set Attestation Policy
    async fn set_policy(&self, _policy_id: &str, _policy: &str) -> anyhow::Result<()> {
        Err(anyhow!("Set Policy API is unimplemented"))
    }

    /// Verify Attestation Evidence
    /// Return Attestation Results Token
    async fn verify(&self, tee: Tee, nonce: &str, attestation: &str) -> anyhow::Result<String>;

    /// generate the Challenge to pass to attester based on Tee and nonce
    async fn generate_challenge(
        &self,
        tee: Tee,
        tee_parameters: serde_json::Value,
    ) -> anyhow::Result<Challenge> {
        generic_generate_challenge(tee, tee_parameters).await
    }
}

/// Attestation Service
#[derive(Clone)]
pub struct AttestationService {
    /// Attestation Module
    inner: Arc<dyn Attest>,

    /// A concurrent safe map to keep status of RCAR status
    session_map: Arc<SessionMap>,

    /// Maximum session expiration time.
    timeout: i64,
}

#[derive(Deserialize, Debug)]
pub struct SetPolicyInput {
    policy_id: String,
    policy: String,
}

impl AttestationService {
    pub async fn new(config: AttestationConfig) -> Result<Self> {
        let inner = match config.attestation_service {
            #[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
            AttestationServiceConfig::CoCoASBuiltIn(cfg) => {
                let built_in_as = super::coco::builtin::BuiltInCoCoAs::new(cfg)
                    .await
                    .map_err(|e| Error::AttestationServiceInitialization { source: e })?;
                Arc::new(built_in_as) as _
            }
            #[cfg(feature = "coco-as-grpc")]
            AttestationServiceConfig::CoCoASGrpc(cfg) => {
                let grpc_coco_as = super::coco::grpc::GrpcClientPool::new(cfg)
                    .await
                    .map_err(|e| Error::AttestationServiceInitialization { source: e })?;
                Arc::new(grpc_coco_as) as _
            }
            #[cfg(feature = "intel-trust-authority-as")]
            AttestationServiceConfig::IntelTA(cfg) => {
                let intel_ta = super::intel_trust_authority::IntelTrustAuthority::new(cfg)
                    .await
                    .map_err(|e| Error::AttestationServiceInitialization { source: e })?;
                Arc::new(intel_ta) as _
            }
        };

        let session_map = Arc::new(SessionMap::new());

        tokio::spawn({
            let session_map_clone = session_map.clone();
            async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    session_map_clone
                        .sessions
                        .retain_async(|_, v| !v.is_expired())
                        .await;
                }
            }
        });
        Ok(Self {
            inner,
            timeout: config.timeout,
            session_map,
        })
    }

    pub async fn set_policy(&self, request: &[u8]) -> Result<()> {
        self.__set_policy(request)
            .await
            .map_err(|e| Error::SetPolicy { source: e })
    }

    async fn __set_policy(&self, request: &[u8]) -> anyhow::Result<()> {
        let input: SetPolicyInput =
            serde_json::from_slice(request).context("parse set policy request")?;
        self.inner.set_policy(&input.policy_id, &input.policy).await
    }

    pub async fn auth(&self, request: &[u8]) -> Result<HttpResponse> {
        self.__auth(request)
            .await
            .map_err(|e| Error::RcarAuthFailed { source: e })
    }

    async fn __auth(&self, request: &[u8]) -> anyhow::Result<HttpResponse> {
        let request: Request = serde_json::from_slice(request).context("deserialize Request")?;
        let version = Version::parse(&request.version).context("failed to parse KBS version")?;
        if !VERSION_REQ.matches(&version) {
            bail!(
                "KBS Client Protocol Version Mismatch: expect {} while the request is {}",
                *VERSION_REQ,
                request.version
            );
        }

        let challenge = self
            .inner
            .generate_challenge(request.tee, request.extra_params.clone())
            .await
            .context("Attestation Service generate challenge failed")?;

        let session = SessionStatus::auth(request, self.timeout, challenge);

        let response = HttpResponse::Ok()
            .cookie(session.cookie())
            .json(session.challenge());

        self.session_map.insert(session);

        Ok(response)
    }

    pub async fn attest(&self, attestation: &[u8], request: HttpRequest) -> Result<HttpResponse> {
        self.__attest(attestation, request)
            .await
            .map_err(|e| Error::RcarAttestFailed { source: e })
    }

    async fn __attest(
        &self,
        attestation: &[u8],
        request: HttpRequest,
    ) -> anyhow::Result<HttpResponse> {
        let cookie = request.cookie(KBS_SESSION_ID).context("cookie not found")?;

        let session_id = cookie.value();

        let attestation: Attestation =
            serde_json::from_slice(attestation).context("deserialize Attestation")?;
        let (tee, nonce) = {
            let session = self
                .session_map
                .sessions
                .get_async(session_id)
                .await
                .ok_or(anyhow!("No cookie found"))?;
            let session = session.get();

            debug!("Session ID {}", session.id());

            if session.is_expired() {
                bail!("session expired.");
            }

            if let SessionStatus::Attested { token, .. } = session {
                debug!(
                    "Session {} is already attested. Skip attestation and return the old token",
                    session.id()
                );
                let body = serde_json::to_string(&json!({
                    "token": token,
                }))
                .context("Serialize token failed")?;

                return Ok(HttpResponse::Ok()
                    .cookie(session.cookie())
                    .content_type("application/json")
                    .body(body));
            }

            let attestation_str = serde_json::to_string_pretty(&attestation)
                .context("Failed to serialize Attestation")?;
            debug!("Attestation: {attestation_str}");

            (session.request().tee, session.challenge().nonce.to_string())
        };

        let attestation_str =
            serde_json::to_string(&attestation).context("serialize attestation failed")?;
        let token = self
            .inner
            .verify(tee, &nonce, &attestation_str)
            .await
            .context("verify TEE evidence failed")?;

        let mut session = self
            .session_map
            .sessions
            .get_async(session_id)
            .await
            .ok_or(anyhow!("session not found"))?;
        let session = session.get_mut();

        session.attest(&token)?;

        let public_key = session.public_key()?;

        let body = serde_json::to_string(&json!({
            "token": token,
            "public_key": public_key
        }))
        .context("Serialize token failed")?;

        Ok(HttpResponse::Ok()
            .cookie(session.cookie())
            .content_type("application/json")
            .body(body))
    }

    pub async fn get_attest_token_from_session(
        &self,
        request: &HttpRequest,
    ) -> anyhow::Result<String> {
        let cookie = request
            .cookie(KBS_SESSION_ID)
            .context("KBS session cookie not found")?;

        let session = self
            .session_map
            .sessions
            .get_async(cookie.value())
            .await
            .context("session not found")?;

        let session = session.get();

        info!("Cookie {} request to get resource", session.id());

        if session.is_expired() {
            bail!("The session is expired");
        }

        let SessionStatus::Attested { token, .. } = session else {
            bail!("The session is not authorized");
        };

        Ok(token.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_make_nonce() {
        const BITS_PER_BYTE: usize = 8;

        /// A base-64 encoded value is this many bits in length.
        const BASE64_BITS_CHUNK: usize = 6;

        /// Number of bytes that base64 encoding requires the result to align on.
        const BASE64_ROUNDING_MULTIPLE: usize = 4;

        /// The nominal base64 encoded length.
        const BASE64_NONCE_LENGTH_UNROUNDED_BYTES: usize =
            (NONCE_SIZE_BYTES * BITS_PER_BYTE) / BASE64_BITS_CHUNK;

        /// The actual base64 encoded length is rounded up to the specified multiple.
        const EXPECTED_LENGTH_BYTES: usize =
            BASE64_NONCE_LENGTH_UNROUNDED_BYTES.next_multiple_of(BASE64_ROUNDING_MULTIPLE);

        // Number of nonce tests to run (arbitrary)
        let nonce_count = 13;

        let mut nonces = vec![];

        for _ in 0..nonce_count {
            let nonce = make_nonce().await.unwrap();

            assert_eq!(nonce.len(), EXPECTED_LENGTH_BYTES);

            let found = nonces.contains(&nonce);

            // The nonces should be unique
            assert_eq!(found, false);

            nonces.push(nonce);
        }
    }
}
