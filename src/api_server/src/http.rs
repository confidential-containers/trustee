// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use attestation_service::AttestationService;
use kbs_types::{Attestation, Challenge, Request};
use std::sync::{Arc, Mutex};

use crate::session::{tee_to_string, Session, SessionMap, KBS_SESSION_ID};

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap<'_>>,
) -> HttpResponse {
    log::info!("request: {:?}", &request);

    let session = match Session::from_request(&request) {
        Ok(s) => s,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .message_body(BoxBody::new(format!("{}", err)))
                .unwrap();
        }
    };
    let response = HttpResponse::Ok().cookie(session.cookie()).json(Challenge {
        nonce: session.nonce().to_string(),
        extra_params: "".to_string(),
    });

    map.sessions
        .write()
        .unwrap()
        .insert(session.id().to_string(), Arc::new(Mutex::new(session)));

    response
}

/// POST /attest
pub(crate) async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    map: web::Data<SessionMap<'_>>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> HttpResponse {
    if let Some(cookie) = request.cookie(KBS_SESSION_ID) {
        if let Some(locked_session) = map.sessions.read().unwrap().get(cookie.value()) {
            let mut session = locked_session.lock().unwrap();

            log::info!("Cookie {} attestation {:?}", session.id(), attestation);

            if !session.is_expired() {
                match attestation_service
                    .evaluate(
                        tee_to_string(&session.tee()),
                        session.nonce(),
                        &attestation.tee_evidence,
                    )
                    .await
                {
                    Ok(results) => {
                        if !results.allow() {
                            return HttpResponse::Unauthorized().finish();
                        }

                        session.set_attestation_results(results);
                        return HttpResponse::Ok().cookie(session.cookie()).finish();
                    }
                    Err(err) => {
                        return HttpResponse::InternalServerError()
                            .message_body(BoxBody::new(format!("{}", err)))
                            .unwrap();
                    }
                };

            }
        }
    }

    HttpResponse::Unauthorized().finish()
}
