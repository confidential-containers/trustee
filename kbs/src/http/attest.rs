// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::{raise_error, session::SessionStatus};

use super::*;

use anyhow::anyhow;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use kbs_types::Challenge;
use log::{debug, error, info};
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use serde_json::json;

static KBS_MAJOR_VERSION: u64 = 0;
static KBS_MINOR_VERSION: u64 = 1;
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

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap>,
    timeout: web::Data<i64>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> Result<HttpResponse> {
    info!("Auth API called.");
    debug!("Auth Request: {:?}", &request);
    let version = Version::parse(&request.version).unwrap();
    if !VERSION_REQ.matches(&version) {
        raise_error!(Error::ProtocolVersion(format!(
            "expected version: {}, requested version: {}",
            *VERSION_REQ,
            request.version.clone()
        )));
    }

    let challenge = attestation_service
        .generate_challenge(request.tee, request.extra_params.clone())
        .await
        .map_err(|e| Error::FailedAuthentication(format!("generate challenge: {e:?}")))?;

    let session = SessionStatus::auth(request.0, **timeout, challenge)
        .map_err(|e| Error::FailedAuthentication(format!("Session: {e}")))?;

    let response = HttpResponse::Ok()
        .cookie(session.cookie())
        .json(session.challenge());

    map.insert(session);

    Ok(response)
}

/// POST /attest
pub(crate) async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    map: web::Data<SessionMap>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> Result<HttpResponse> {
    info!("Attest API called.");
    let cookie = request.cookie(KBS_SESSION_ID).ok_or(Error::MissingCookie)?;

    let (tee, nonce) = {
        let session = map
            .sessions
            .get_async(cookie.value())
            .await
            .ok_or(Error::InvalidCookie)?;
        let session = session.get();

        debug!("Session ID {}", session.id());

        if session.is_expired() {
            raise_error!(Error::ExpiredCookie);
        }

        if let SessionStatus::Attested { token, .. } = session {
            debug!(
                "Session {} is already attested. Skip attestation and return the old token",
                session.id()
            );
            let body = serde_json::to_string(&json!({
                "token": token,
            }))
            .map_err(|e| Error::TokenIssueFailed(format!("Serialize token failed {e}")))?;

            return Ok(HttpResponse::Ok()
                .cookie(session.cookie())
                .content_type("application/json")
                .body(body));
        }

        let attestation_str = serde_json::to_string_pretty(&attestation.0)
            .map_err(|_| Error::AttestationFailed("Failed to serialize Attestation".into()))?;
        debug!("Attestation: {attestation_str}");

        (session.request().tee, session.challenge().nonce.to_string())
    };

    let attestation_str = serde_json::to_string(&attestation)
        .map_err(|e| Error::AttestationFailed(format!("serialize attestation failed : {e:?}")))?;
    let token = attestation_service
        .verify(tee, &nonce, &attestation_str)
        .await
        .map_err(|e| Error::AttestationFailed(format!("{e:?}")))?;

    let claims_b64 = token
        .split('.')
        .nth(1)
        .ok_or_else(|| Error::TokenIssueFailed("Illegal token format".to_string()))?;
    let claims = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(claims_b64)
            .map_err(|e| Error::TokenIssueFailed(format!("Illegal token base64 claims: {e}")))?,
    )
    .map_err(|e| Error::TokenIssueFailed(format!("Illegal token base64 claims: {e}")))?;

    let mut session = map
        .sessions
        .get_async(cookie.value())
        .await
        .ok_or(Error::InvalidCookie)?;
    let session = session.get_mut();

    let body = serde_json::to_string(&json!({
        "token": token,
    }))
    .map_err(|e| Error::TokenIssueFailed(format!("Serialize token failed {e}")))?;

    session.attest(claims, token);

    Ok(HttpResponse::Ok()
        .cookie(session.cookie())
        .content_type("application/json")
        .body(body))
}
