// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;

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

/// GET /resource/{repository}/{type}/{tag}
/// GET /resource/{type}/{tag}
pub(crate) async fn get_resource(
    request: HttpRequest,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
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

    log::info!("Resource description: {:?}", &resource_description);

    if session.tee_public_key().is_none() {
        internal!(format!("TEE Pubkey not found"));
    }

    let resource_byte = match repository
        .read()
        .await
        .read_secret_resource(resource_description)
        .await
    {
        Ok(byte) => byte,
        Err(e) => internal!(format!(
            "Read secret resource from repository failed: {:?}",
            e
        )),
    };

    match session.to_jwe(resource_byte) {
        Ok(response) => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&response).unwrap()),
        Err(e) => internal!(format!("Generate Confidential Response failed: {e}")),
    }
}
