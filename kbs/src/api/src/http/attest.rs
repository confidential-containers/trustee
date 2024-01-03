// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::raise_error;

use super::*;

use anyhow::anyhow;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::{error, info};
use serde_json::json;

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap<'_>>,
    timeout: web::Data<i64>,
) -> Result<HttpResponse> {
    info!("request: {:?}", &request);

    let session = Session::from_request(&request, *timeout.into_inner())
        .map_err(|e| Error::FailedAuthentication(format!("Session: {e}")))?;
    let response = HttpResponse::Ok().cookie(session.cookie()).json(Challenge {
        nonce: session.nonce().to_string(),
        extra_params: "".to_string(),
    });

    let _ = map.sessions.insert(session.id().to_string(), session);

    Ok(response)
}

/// POST /attest
pub(crate) async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    map: web::Data<SessionMap<'_>>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> Result<HttpResponse> {
    let cookie = request.cookie(KBS_SESSION_ID).ok_or(Error::MissingCookie)?;

    let (tee, nonce) = {
        let session = map
            .sessions
            .get_async(cookie.value())
            .await
            .ok_or(Error::InvalidCookie)?;
        let session = session.get();

        info!("Cookie {} attestation {:?}", session.id(), attestation);

        if session.is_expired() {
            raise_error!(Error::ExpiredCookie);
        }
        (session.tee(), session.nonce().to_string())
    };

    let token = attestation_service
        .verify(tee, &nonce, &serde_json::to_string(&attestation).unwrap())
        .await
        .map_err(|e| Error::AttestationFailed(e.to_string()))?;

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
    session.set_tee_public_key(attestation.tee_pubkey.clone());
    session.set_authenticated();
    session.set_attestation_claims(claims);

    let body = serde_json::to_string(&json!({
        "token": token,
    }))
    .map_err(|e| Error::TokenIssueFailed(format!("Serialize token failed {e}")))?;

    Ok(HttpResponse::Ok()
        .cookie(session.cookie())
        .content_type("application/json")
        .body(body))
}
