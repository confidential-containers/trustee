// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::raise_error;

use super::*;

use anyhow::anyhow;
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

    map.sessions
        .write()
        .await
        .insert(session.id().to_string(), Arc::new(Mutex::new(session)));

    Ok(response)
}

/// POST /attest
pub(crate) async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    token_broker: web::Data<Arc<RwLock<dyn AttestationTokenBroker + Send + Sync>>>,
    map: web::Data<SessionMap<'_>>,
    timeout: web::Data<i64>,
    attestation_service: web::Data<AttestationService>,
) -> Result<HttpResponse> {
    let cookie = request.cookie(KBS_SESSION_ID).ok_or(Error::MissingCookie)?;

    let sessions = map.sessions.read().await;
    let locked_session = sessions.get(cookie.value()).ok_or(Error::InvalidCookie)?;

    let mut session = locked_session.lock().await;

    info!("Cookie {} attestation {:?}", session.id(), attestation);

    if session.is_expired() {
        raise_error!(Error::ExpiredCookie);
    }

    let results = attestation_service
        .0
        .lock()
        .await
        .verify(
            session.tee(),
            session.nonce(),
            &serde_json::to_string(&attestation).unwrap(),
        )
        .await
        .map_err(|e| Error::AttestationFailed(e.to_string()))?;

    if !results.allow() {
        error!("Evidence verification failed {:?}", results.output());
        raise_error!(Error::AttestationFailed(String::from(
            "evidence verification failed"
        )));
    }

    session.set_tee_public_key(attestation.tee_pubkey.clone());
    session.set_attestation_results(results.clone());

    let token_claims = json!({
        "tee-pubkey": attestation.tee_pubkey.clone(),
        "attestation-results": results.clone(),
    });
    let token = token_broker
        .read()
        .await
        .issue(token_claims, *timeout.into_inner() as usize)
        .map_err(|e| Error::TokenIssueFailed(e.to_string()))?;

    let body = serde_json::to_string(&json!({
        "token": token,
    }))
    .map_err(|e| Error::TokenIssueFailed(format!("Serialize token failed {e}")))?;

    Ok(HttpResponse::Ok()
        .cookie(session.cookie())
        .content_type("application/json")
        .body(body))
}
