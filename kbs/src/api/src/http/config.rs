// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[cfg(feature = "as")]
/// POST /attestation-policy
pub(crate) async fn attestation_policy(
    request: HttpRequest,
    input: web::Bytes,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure_api: web::Data<bool>,
    attestation_service: web::Data<Arc<AttestationService>>,
) -> Result<HttpResponse> {
    if !insecure_api.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    attestation_service
        .set_policy(&input)
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Set policy error {e}")))?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "policy")]
/// POST /resource-policy
pub(crate) async fn resource_policy(
    request: HttpRequest,
    input: web::Json<serde_json::Value>,
    user_pub_key: web::Data<Option<Ed25519PublicKey>>,
    insecure_api: web::Data<bool>,
    policy_engine: web::Data<PolicyEngine>,
) -> Result<HttpResponse> {
    if !insecure_api.get_ref() {
        let user_pub_key = user_pub_key
            .as_ref()
            .as_ref()
            .ok_or(Error::UserPublicKeyNotProvided)?;

        validate_auth(&request, user_pub_key).map_err(|e| {
            Error::FailedAuthentication(format!("Requester is not an authorized user: {e}"))
        })?;
    }

    policy_engine
        .0
        .lock()
        .await
        .set_policy(
            input.into_inner()["policy"]
                .as_str()
                .ok_or(Error::PolicyEndpoint(
                    "Get policy from request failed".to_string(),
                ))?
                .to_string(),
        )
        .await
        .map_err(|e| Error::PolicyEndpoint(format!("Set policy error {e}")))?;

    Ok(HttpResponse::Ok().finish())
}

#[cfg(feature = "resource")]
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
    insecure_api: web::Data<bool>,
    repository: web::Data<Arc<RwLock<dyn Repository + Send + Sync>>>,
) -> Result<HttpResponse> {
    if !insecure_api.get_ref() {
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
