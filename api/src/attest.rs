// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use serde_json::json;

macro_rules! unauthorized {
    ($error_type: ident, $reason: expr) => {
        return HttpResponse::Unauthorized()
            .json(error_info(ErrorInformationType::$error_type, $reason))
    };
}

macro_rules! internal {
    ($reason: expr) => {
        return HttpResponse::InternalServerError()
            .message_body(BoxBody::new($reason))
            .unwrap()
    };
}

macro_rules! bail_error_internal {
    ($error: expr) => {
        match $error {
            Ok(inner) => inner,
            Err(e) => {
                return HttpResponse::InternalServerError()
                    .message_body(BoxBody::new(e.to_string()))
                    .unwrap()
            }
        }
    };
}

/// POST /auth
pub async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap<'_>>,
    timeout: web::Data<i64>,
) -> HttpResponse {
    log::info!("request: {:?}", &request);

    let session = match Session::from_request(&request, *timeout.into_inner()) {
        Ok(s) => s,
        Err(err) => {
            return HttpResponse::InternalServerError().json(error_info(
                ErrorInformationType::FailedAuthentication,
                &format!("{err}"),
            ));
        }
    };
    let response = HttpResponse::Ok().cookie(session.cookie()).json(Challenge {
        nonce: session.nonce().to_string(),
        extra_params: "".to_string(),
    });

    map.sessions
        .write()
        .await
        .insert(session.id().to_string(), Arc::new(Mutex::new(session)));

    response
}

/// POST /attest
pub async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    token_broker: web::Data<Arc<RwLock<dyn AttestationTokenBroker + Send + Sync>>>,
    map: web::Data<SessionMap<'_>>,
    timeout: web::Data<i64>,
    attestation_service: web::Data<AttestationService>,
) -> HttpResponse {
    let cookie = match request.cookie(KBS_SESSION_ID) {
        Some(c) => c,
        None => {
            log::error!("Missing KBS cookie");
            unauthorized!(MissingCookie, "");
        }
    };

    let sessions = map.sessions.read().await;
    let locked_session = match sessions.get(cookie.value()) {
        Some(ls) => ls,
        None => {
            log::error!("Invalid KBS cookie {}", cookie.value());
            unauthorized!(InvalidCookie, cookie.value());
        }
    };

    let mut session = locked_session.lock().await;

    log::info!("Cookie {} attestation {:?}", session.id(), attestation);

    if session.is_expired() {
        log::error!("Expired KBS cookie {}", cookie.value());
        unauthorized!(ExpiredCookie, cookie.value());
    }

    match attestation_service
        .0
        .lock()
        .await
        .verify(
            session.tee(),
            session.nonce(),
            &serde_json::to_string(&attestation).unwrap(),
        )
        .await
    {
        Ok(results) => {
            if !results.allow() {
                log::error!("Evidence verification failed {:?}", results.output());
                unauthorized!(VerificationFailed, "Attestation failure");
            }

            session.set_tee_public_key(attestation.tee_pubkey.clone());
            session.set_attestation_results(results.clone());

            let token_claims = json!({
                "tee-pubkey": attestation.tee_pubkey.clone(),
                "attestation-results": results.clone(),
            });
            let token = match token_broker
                .read()
                .await
                .issue(token_claims, *timeout.into_inner() as usize)
            {
                Ok(token) => token,
                Err(e) => internal!(format!("Issue Attestation Token failed: {e}")),
            };
            HttpResponse::Ok()
                .cookie(session.cookie())
                .content_type("application/json")
                .body(bail_error_internal!(serde_json::to_string(&json!({
                    "token": token,
                }))))
        }
        Err(err) => internal!(format!("{err}")),
    }
}
