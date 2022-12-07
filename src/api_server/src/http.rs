// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use attestation_service::AttestationService;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request};
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::Mutex;

use crate::session::{tee_to_string, Session, SessionMap, KBS_SESSION_ID};

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors/";

#[derive(Debug, EnumString)]
pub enum ErrorInformationType {
    ExpiredCookie,
    FailedAuthentication,
    InvalidCookie,
    MissingCookie,
    VerificationFailed,
}

fn kbs_error_info(error_type: ErrorInformationType, detail: &str) -> ErrorInformation {
    ErrorInformation {
        error_type: format!("{ERROR_TYPE_PREFIX}{error_type:?}"),
        detail: detail.to_string(),
    }
}

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap<'_>>,
    timeout: web::Data<i64>,
) -> HttpResponse {
    log::info!("request: {:?}", &request);

    let session = match Session::from_request(&request, *timeout.into_inner()) {
        Ok(s) => s,
        Err(err) => {
            return HttpResponse::InternalServerError().json(kbs_error_info(
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
pub(crate) async fn attest(
    attestation: web::Json<Attestation>,
    request: HttpRequest,
    map: web::Data<SessionMap<'_>>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> HttpResponse {
    let error_info = if let Some(cookie) = request.cookie(KBS_SESSION_ID) {
        if let Some(locked_session) = map.sessions.read().await.get(cookie.value()) {
            let mut session = locked_session.lock().await;

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
                            log::error!("Evidence verification failed {:?}", results.output());
                            kbs_error_info(
                                ErrorInformationType::VerificationFailed,
                                "Attestation failure",
                            );
                        }

                        session.set_tee_public_key(attestation.tee_pubkey.clone());
                        session.set_attestation_results(results);
                        return HttpResponse::Ok().cookie(session.cookie()).finish();
                    }
                    Err(err) => {
                        return HttpResponse::InternalServerError()
                            .message_body(BoxBody::new(format!("{err}")))
                            .unwrap();
                    }
                };
            } else {
                log::error!("Expired KBS cookie {}", cookie.value());
                kbs_error_info(ErrorInformationType::ExpiredCookie, cookie.value())
            }
        } else {
            log::error!("Invalid KBS cookie {}", cookie.value());
            kbs_error_info(ErrorInformationType::InvalidCookie, cookie.value())
        }
    } else {
        log::error!("Missing KBS cookie");
        kbs_error_info(ErrorInformationType::MissingCookie, "")
    };

    HttpResponse::Unauthorized().json(error_info)
}
