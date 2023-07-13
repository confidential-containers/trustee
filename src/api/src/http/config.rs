// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;

/// POST /attestation-policy
pub(crate) async fn attestation_policy(
    request: HttpRequest,
    input: web::Json<as_types::SetPolicyInput>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    attestation_service: web::Data<AttestationService>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    attestation_service
        .0
        .lock()
        .await
        .set_policy(input.into_inner())
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Set policy error {e}")))?;

    Ok(HttpResponse::Ok().finish())
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
pub(crate) async fn set_resource(
    request: HttpRequest,
    data: web::Bytes,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure: web::Data<bool>,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
) -> Result<HttpResponse> {
    if !insecure.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
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

    set_secret_resource(&repository, resource_description, data.as_ref())
        .await
        .map_err(|e| Error::SetSecretFailed(format!("{e}")))?;
    Ok(HttpResponse::Ok().content_type("application/json").body(""))
}
