// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;

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

/// POST /attestation-policy
pub async fn attestation_policy(
    request: HttpRequest,
    input: web::Json<as_types::SetPolicyInput>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    attestation_service: web::Data<AttestationService>,
) -> HttpResponse {
    if !insecure.get_ref() {
        let user_pub_key = match user_pub_key.as_ref() {
            Some(key) => key,
            None => internal!("No user public key provided"),
        };

        if let Err(e) = validate_auth(&request, user_pub_key) {
            log::error!("auth validate verified failed: {e}");
            unauthorized!(
                JWTVerificationFailed,
                &format!("Authentication failed: {e}")
            );
        }
    }

    match attestation_service
        .0
        .lock()
        .await
        .set_policy(input.into_inner())
        .await
    {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(err) => internal!(format!("{err}")),
    }
}

/// POST /resource/{repository}/{type}/{tag}
/// POST /resource/{type}/{tag}
///
/// TODO: Although this endpoint is authenticated through a JSON Web Token (JWT),
/// only identified users should be able to get a JWT and access it.
/// At the moment user identification is not supported, and the KBS CLI
/// `--user-public-key` defines the authorized user for that endpoint. In other words,
/// any JWT signed with the user's private key will be authenticated.
/// JWT generation and user identification is unimplemented for now, and thus this
/// endpoint is insecure and is only meant for testing purposes.
pub async fn set_resource(
    request: HttpRequest,
    data: web::Bytes,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
) -> HttpResponse {
    if !insecure.get_ref() {
        let user_pub_key = match user_pub_key.as_ref() {
            Some(key) => key,
            None => internal!("No user public key provided"),
        };

        if let Err(e) = validate_auth(&request, user_pub_key) {
            log::error!("auth validate verified failed: {e}");
            unauthorized!(
                JWTVerificationFailed,
                &format!("Authentication failed: {e}")
            );
        }
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

    match set_secret_resource(&repository, resource_description, data.as_ref()).await {
        Ok(_) => HttpResponse::Ok().content_type("application/json").body(""),
        Err(e) => {
            log::error!("Resource registration failed: {e}");
            internal!(format!("Resource registration failed: {e}"));
        }
    }
}
