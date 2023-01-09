// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse};
use attestation_service::AttestationService;
use kbs_types::{Attestation, Challenge, ErrorInformation, Request};
use std::sync::Arc;
use strum_macros::EnumString;
use tokio::sync::Mutex;

use crate::resource::{secret_resource, Repository, ResourceDesc};
use crate::session::{Session, SessionMap, KBS_SESSION_ID};

const ERROR_TYPE_PREFIX: &str = "https://github.com/confidential-containers/kbs/errors/";

#[derive(Debug, EnumString)]
pub enum ErrorInformationType {
    ExpiredCookie,
    FailedAuthentication,
    InvalidCookie,
    MissingCookie,
    UnAuthenticatedCookie,
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
                        session.tee(),
                        session.nonce(),
                        &serde_json::to_string(&attestation).unwrap(),
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

/// GET /resource/{repository}/{type}/{tag}
/// GET /resource/{type}/{tag}
pub(crate) async fn resource(
    request: HttpRequest,
    repository: web::Data<Arc<dyn Repository + Send + Sync>>,
    map: web::Data<SessionMap<'_>>,
) -> HttpResponse {
    let cookie = match request.cookie(KBS_SESSION_ID) {
        None => {
            log::error!("Missing KBS cookie");
            return HttpResponse::Unauthorized()
                .json(kbs_error_info(ErrorInformationType::MissingCookie, ""));
        }
        Some(c) => c,
    };

    let session_map = map.sessions.read().await;
    let locked_session = match session_map.get(cookie.value()) {
        None => {
            log::error!("Invalid KBS cookie {}", cookie.value());
            return HttpResponse::Unauthorized().json(kbs_error_info(
                ErrorInformationType::InvalidCookie,
                cookie.value(),
            ));
        }
        Some(ls) => ls,
    };

    let session = locked_session.lock().await;

    log::info!("Cookie {} request to get resource", session.id());

    if !session.is_authenticated() {
        log::error!("UnAuthenticated KBS cookie {}", cookie.value());
        return HttpResponse::Unauthorized().json(kbs_error_info(
            ErrorInformationType::UnAuthenticatedCookie,
            cookie.value(),
        ));
    }

    if session.is_expired() {
        log::error!("Expired KBS cookie {}", cookie.value());
        return HttpResponse::Unauthorized().json(kbs_error_info(
            ErrorInformationType::ExpiredCookie,
            cookie.value(),
        ));
    }

    let resource_description = ResourceDesc {
        repository_name: request
            .match_info()
            .get("repository")
            .unwrap_or("default")
            .to_string(),
        resource_type: request.match_info().get("type").unwrap().to_string(),
        resource_tag: request.match_info().get("tag").unwrap().to_string(),
    };

    if resource_description.resource_type == "token" {
        // TODO: Distribute attestation token (Passport).
        return HttpResponse::NotFound()
            .message_body(BoxBody::new(
                "Token resource is unsupported now".to_string(),
            ))
            .unwrap();
    }

    log::info!("Resource description: {:?}", &resource_description);

    if session.tee_public_key().is_none() {
        return HttpResponse::InternalServerError()
            .message_body(BoxBody::new("TEE Pubkey not found"))
            .unwrap();
    }

    match secret_resource(
        session.tee_public_key().unwrap(),
        repository.get_ref(),
        resource_description,
    ) {
        Ok(response) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&response).unwrap()),
        Err(e) => HttpResponse::InternalServerError()
            .message_body(BoxBody::new(format!("Get Resource failed: {e}")))
            .unwrap(),
    }
}
