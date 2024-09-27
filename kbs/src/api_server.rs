// Copyright (c) 2023 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{
    http::{header::Header, Method},
    middleware, web, App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use log::info;

use crate::{
    admin::Admin, config::KbsConfig, jwe::jwe, plugins::PluginManager, policy_engine::PolicyEngine,
    resource::ResourceDesc, token::TokenVerifier, Error, Result,
};

const KBS_PREFIX: &str = "/kbs/v0";

macro_rules! kbs_path {
    ($path:expr) => {
        format!("{}/{}", KBS_PREFIX, $path)
    };
}

/// The KBS API server
#[derive(Clone)]
pub struct ApiServer {
    plugin_manager: PluginManager,

    #[cfg(feature = "resource")]
    resource_storage: crate::resource::ResourceStorage,

    #[cfg(feature = "as")]
    attestation_service: crate::attestation::AttestationService,

    policy_engine: PolicyEngine,
    admin_auth: Admin,
    config: KbsConfig,
    token_verifier: TokenVerifier,
}

impl ApiServer {
    async fn get_attestation_token(&self, request: &HttpRequest) -> anyhow::Result<String> {
        #[cfg(feature = "as")]
        if let Ok(token) = self
            .attestation_service
            .get_attest_token_from_session(request)
            .await
        {
            return Ok(token);
        }

        let bearer = Authorization::<Bearer>::parse(request)
            .context("parse Authorization header failed")?
            .into_scheme();

        let token = bearer.token().to_string();

        Ok(token)
    }

    pub async fn new(config: KbsConfig) -> Result<Self> {
        let plugin_manager = PluginManager::try_from(config.client_plugins.clone())?;
        let token_verifier = TokenVerifier::from_config(config.attestation_token.clone()).await?;
        let policy_engine = PolicyEngine::new(&config.policy_engine).await?;
        let admin_auth = Admin::try_from(config.admin.clone())?;

        #[cfg(feature = "resource")]
        let resource_storage =
            crate::resource::ResourceStorage::try_from(config.repository.clone())?;

        #[cfg(feature = "as")]
        let attestation_service =
            crate::attestation::AttestationService::new(config.attestation_service.clone()).await?;

        Ok(Self {
            config,
            plugin_manager,
            policy_engine,
            admin_auth,
            token_verifier,

            #[cfg(feature = "resource")]
            resource_storage,

            #[cfg(feature = "as")]
            attestation_service,
        })
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(self) -> Result<()> {
        info!(
            "Starting HTTP{} server at {:?}",
            if !self.config.http_server.insecure_http {
                "S"
            } else {
                ""
            },
            self.config.http_server.sockets
        );

        let http_config = self.config.http_server.clone();
        let http_server = HttpServer::new({
            move || {
                let api_server = self.clone();
                App::new()
                    .wrap(middleware::Logger::default())
                    .app_data(web::Data::new(api_server))
                    .service(
                        web::resource([kbs_path!("{plugin}{sub_path:.*}")])
                            .route(web::get().to(client))
                            .route(web::post().to(client)),
                    )
                    .service(
                        web::resource([kbs_path!("admin/{plugin}/{sub_path:.*}")])
                            .route(web::get().to(admin))
                            .route(web::post().to(admin)),
                    )
            }
        });

        if !http_config.insecure_http {
            let tls_server = http_server
                .bind_openssl(
                    &http_config.sockets[..],
                    crate::http::tls_config(&http_config)
                        .map_err(|e| Error::HTTPSFailed { source: e })?,
                )
                .map_err(|e| Error::HTTPSFailed { source: e.into() })?;

            return tls_server
                .run()
                .await
                .map_err(|e| Error::HTTPSFailed { source: e.into() });
        }

        http_server
            .bind(&http_config.sockets[..])
            .map_err(|e| Error::HTTPFailed { source: e.into() })?
            .run()
            .await
            .map_err(|e| Error::HTTPFailed { source: e.into() })
    }
}

/// Client APIs. /kbs/v0/XXX
pub(crate) async fn client(
    request: HttpRequest,
    body: web::Bytes,
    core: web::Data<ApiServer>,
) -> Result<HttpResponse> {
    let query = request.query_string();
    let plugin_name = request
        .match_info()
        .get("plugin")
        .ok_or(Error::IllegalAccessedPath {
            path: request.path().to_string(),
        })?;
    let sub_path = request
        .match_info()
        .get("sub_path")
        .ok_or(Error::IllegalAccessedPath {
            path: request.path().to_string(),
        })?;

    let end_point = format!("{plugin_name}{sub_path}");

    match plugin_name {
        #[cfg(feature = "as")]
        "auth" if request.method() == Method::POST => core
            .attestation_service
            .auth(&body)
            .await
            .map_err(From::from),
        #[cfg(feature = "as")]
        "attest" if request.method() == Method::POST => core
            .attestation_service
            .attest(&body, request)
            .await
            .map_err(From::from),
        #[cfg(feature = "as")]
        "attestation-policy" if request.method() == Method::POST => {
            core.admin_auth.validate_auth(&request)?;

            core.attestation_service.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        "resource-policy" if request.method() == Method::POST => {
            core.admin_auth.validate_auth(&request)?;

            core.policy_engine.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        #[cfg(feature = "resource")]
        "resource" => {
            if request.method() == Method::GET {
                // Resource APIs needs to be authorized by the Token and policy
                let resource_desc =
                    sub_path
                        .strip_prefix('/')
                        .ok_or(Error::IllegalAccessedPath {
                            path: end_point.clone(),
                        })?;

                let token = core
                    .get_attestation_token(&request)
                    .await
                    .map_err(|_| Error::TokenNotFound)?;

                let claims = core.token_verifier.verify(token).await?;

                let claim_str = serde_json::to_string(&claims)?;
                if !core
                    .policy_engine
                    .evaluate(resource_desc, &claim_str)
                    .await?
                {
                    return Err(Error::PolicyDeny);
                };

                let resource_description = ResourceDesc::try_from(resource_desc)?;
                let resource = core
                    .resource_storage
                    .get_secret_resource(resource_description)
                    .await?;

                let public_key = core.token_verifier.extract_tee_public_key(claims)?;
                let jwe = jwe(public_key, resource).map_err(|e| Error::JweError { source: e })?;

                let res = serde_json::to_string(&jwe)?;

                Ok(HttpResponse::Ok()
                    .content_type("application/json")
                    .body(res))
            } else if request.method() == Method::POST {
                let resource_desc =
                    sub_path
                        .strip_prefix('/')
                        .ok_or(Error::IllegalAccessedPath {
                            path: end_point.clone(),
                        })?;
                let resource_description = ResourceDesc::try_from(resource_desc)?;
                core.admin_auth.validate_auth(&request)?;
                core.resource_storage
                    .set_secret_resource(resource_description, &body)
                    .await?;

                Ok(HttpResponse::Ok().content_type("application/json").body(""))
            } else {
                Ok(HttpResponse::NotImplemented()
                    .content_type("application/json")
                    .body(""))
            }
        }
        plugin_name => {
            // Plugin calls needs to be authorized by the Token and policy
            let token = core
                .get_attestation_token(&request)
                .await
                .map_err(|_| Error::TokenNotFound)?;

            let claims = core.token_verifier.verify(token).await?;

            let claim_str = serde_json::to_string(&claims)?;

            // TODO: add policy filter support for other plugins
            if !core.policy_engine.evaluate(&end_point, &claim_str).await? {
                return Err(Error::PolicyDeny);
            }

            let plugin = core
                .plugin_manager
                .get(plugin_name)
                .ok_or(Error::PluginNotFound {
                    plugin_name: plugin_name.to_string(),
                })?;
            let body = body.to_vec();
            let response = plugin
                .handle(body, query.into(), sub_path.into(), request.method())
                .await?;
            Ok(response)
        }
    }
}

/// Admin APIs.
pub(crate) async fn admin(
    request: HttpRequest,
    _body: web::Bytes,
    core: web::Data<ApiServer>,
) -> Result<HttpResponse> {
    // Admin APIs needs to be authorized by the admin asymmetric key
    core.admin_auth.validate_auth(&request)?;

    let plugin_name = request
        .match_info()
        .get("plugin")
        .ok_or(Error::IllegalAccessedPath {
            path: request.path().to_string(),
        })?;
    let sub_path = request
        .match_info()
        .get("sub_path")
        .ok_or(Error::IllegalAccessedPath {
            path: request.path().to_string(),
        })?;

    info!("Admin plugin {plugin_name} with path {sub_path} called");

    // TODO: add admin path handlers
    let response = HttpResponse::NotFound().body("no admin plugin found");
    Ok(response)
}
