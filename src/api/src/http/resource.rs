// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail};
use log::{error, info};

use crate::raise_error;

use super::*;

/// GET /resource/{repository}/{type}/{tag}
/// GET /resource/{type}/{tag}
pub(crate) async fn get_resource(
    request: HttpRequest,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
    map: web::Data<SessionMap<'_>>,
) -> Result<HttpResponse> {
    let cookie = request
        .cookie(KBS_SESSION_ID)
        .ok_or(Error::UnAuthenticatedCookie)?;

    let session_map = map.sessions.read().await;
    let locked_session = session_map
        .get(cookie.value())
        .ok_or(Error::UnAuthenticatedCookie)?;

    let session = locked_session.lock().await;

    info!("Cookie {} request to get resource", session.id());

    if !session.is_authenticated() {
        error!("UnAuthenticated KBS cookie {}", cookie.value());
        raise_error!(Error::UnAuthenticatedCookie);
    }

    if session.is_expired() {
        error!("Expired KBS cookie {}", cookie.value());
        raise_error!(Error::ExpiredCookie);
    }

    let resource_description = ResourceDesc {
        repository_name: request
            .match_info()
            .get("repository")
            .unwrap_or("default")
            .to_string(),
        resource_type: request
            .match_info()
            .get("type")
            .ok_or_else(|| Error::InvalidRequest(String::from("no `type` in url")))?
            .to_string(),
        resource_tag: request
            .match_info()
            .get("tag")
            .ok_or_else(|| Error::InvalidRequest(String::from("no `tag` in url")))?
            .to_string(),
    };

    info!("Resource description: {:?}", &resource_description);

    if session.tee_public_key().is_none() {
        error!("TEE pubkey not found");
        raise_error!(Error::FailedAuthentication(String::from(
            "Teepub key not found in session"
        )));
    }

    let resource_byte = repository
        .read()
        .await
        .read_secret_resource(resource_description)
        .await
        .map_err(|e| Error::ReadSecretFailed(e.to_string()))?;

    let jwe = session
        .to_jwe(resource_byte)
        .map_err(|e| Error::JWEFailed(e.to_string()))?;

    let res = serde_json::to_string(&jwe).map_err(|e| Error::JWEFailed(e.to_string()))?;

    Ok(HttpResponse::Ok()
        .content_type("application/json")
        .body(res))
}
