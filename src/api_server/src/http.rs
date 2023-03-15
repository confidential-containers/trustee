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

macro_rules! unauthorized {
    ($error_type: ident, $reason: expr) => {
        return HttpResponse::Unauthorized()
            .json(kbs_error_info(ErrorInformationType::$error_type, $reason))
    };
}

macro_rules! internal {
    ($reason: expr) => {
        return HttpResponse::InternalServerError()
            .message_body(BoxBody::new($reason))
            .unwrap()
    };
}

macro_rules! notfound {
    ($reason: expr) => {
        return HttpResponse::NotFound()
            .message_body(BoxBody::new($reason))
            .unwrap()
    };
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
                unauthorized!(VerificationFailed, "Attestation failure");
            }

            session.set_tee_public_key(attestation.tee_pubkey.clone());
            session.set_attestation_results(results);
            HttpResponse::Ok().cookie(session.cookie()).finish()
        }
        Err(err) => internal!(format!("{err}")),
    }
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
            unauthorized!(MissingCookie, "");
        }
        Some(c) => c,
    };

    let session_map = map.sessions.read().await;
    let locked_session = match session_map.get(cookie.value()) {
        None => {
            log::error!("Invalid KBS cookie {}", cookie.value());
            unauthorized!(InvalidCookie, cookie.value());
        }
        Some(ls) => ls,
    };

    let session = locked_session.lock().await;

    log::info!("Cookie {} request to get resource", session.id());

    if !session.is_authenticated() {
        log::error!("UnAuthenticated KBS cookie {}", cookie.value());
        unauthorized!(UnAuthenticatedCookie, cookie.value());
    }

    if session.is_expired() {
        log::error!("Expired KBS cookie {}", cookie.value());
        unauthorized!(ExpiredCookie, cookie.value());
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
        notfound!("Token resource is unsupported now");
    }

    log::info!("Resource description: {:?}", &resource_description);

    if session.tee_public_key().is_none() {
        internal!(format!("TEE Pubkey not found"));
    }

    match secret_resource(
        session.tee_public_key().unwrap(),
        repository.get_ref(),
        resource_description,
    )
    .await
    {
        Ok(response) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&response).unwrap()),
        Err(e) => internal!(format!("Get Resource failed: {e}")),
    }
}
