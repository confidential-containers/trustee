// Copyright (c) 2023 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use actix_web::{
    http::{header::Header, Method},
    middleware,
    web::{self, Query},
    App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use base64::Engine;
use log::{info, warn};
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::json;

use crate::{
    admin::Admin,
    config::KbsConfig,
    jwe::jwe,
    plugins::PluginManager,
    prometheus::{
        ACTIVE_CONNECTIONS, BUILD_INFO, KBS_POLICY_APPROVALS, KBS_POLICY_ERRORS, KBS_POLICY_EVALS,
        KBS_POLICY_VIOLATIONS, REQUEST_DURATION, REQUEST_SIZES, REQUEST_TOTAL,
    },
    token::TokenVerifier,
    Error, Result,
};

const KBS_PREFIX: &str = "/kbs/v0";

pub const KBS_STORAGE_INSTANCE: &str = "kbs";

macro_rules! kbs_path {
    ($path:expr) => {
        format!("{}/{}", KBS_PREFIX, $path)
    };
}

/// The KBS API server
#[derive(Clone)]
pub struct ApiServer {
    plugin_manager: PluginManager,

    #[cfg(feature = "as")]
    attestation_service: crate::attestation::AttestationService,

    policy_engine: PolicyEngine<Regorus>,
    admin: Admin,
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
        let plugin_manager = PluginManager::new(config.plugins.clone(), &config.storage_backend)
            .await
            .map_err(|e| Error::PluginManagerInitialization { source: e })?;
        let token_verifier = TokenVerifier::from_config(config.attestation_token.clone()).await?;

        let policy_storage_backend = config
            .storage_backend
            .backends
            .to_client_with_instance(config.storage_backend.storage_type, KBS_STORAGE_INSTANCE)
            .await
            .map_err(|e| Error::StorageBackendInitialization { source: e })?;
        let policy_engine = PolicyEngine::new(policy_storage_backend);

        policy_engine
            .set_policy(
                "resource-policy",
                include_str!("./policy/resource-policy.rego"),
                false,
            )
            .await?;
        let admin = Admin::try_from(config.admin.clone())?;

        #[cfg(feature = "as")]
        let attestation_service = crate::attestation::AttestationService::new(
            config.attestation_service.clone(),
            &config.storage_backend,
        )
        .await?;

        BUILD_INFO.inc();

        Ok(Self {
            config,
            plugin_manager,
            policy_engine,
            admin,
            token_verifier,

            #[cfg(feature = "as")]
            attestation_service,
        })
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(self) -> Result<()> {
        actix::spawn(self.server()?)
            .await
            .map_err(|e| Error::HTTPFailed { source: e.into() })?
            .map_err(|e| Error::HTTPFailed { source: e.into() })
    }

    /// Setup API server
    pub fn server(self) -> Result<actix_web::dev::Server> {
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

        #[allow(clippy::redundant_closure)]
        let mut http_server = HttpServer::new({
            move || {
                let api_server = self.clone();
                App::new()
                    .wrap(middleware::Logger::default())
                    .wrap(middleware::from_fn(prometheus_metrics_middleware))
                    .app_data(web::Data::new(api_server))
                    .app_data(web::PayloadConfig::new(
                        (1024 * 1024 * http_config.payload_request_size) as usize,
                    ))
                    .service(
                        web::resource([kbs_path!("{path:.*}")])
                            .route(web::get().to(api))
                            .route(web::post().to(api)),
                    )
                    .service(
                        web::resource("/metrics")
                            .route(web::get().to(prometheus_metrics_handler))
                            .route(web::post().to(|| HttpResponse::MethodNotAllowed())),
                    )
            }
        });

        if let Some(worker_count) = http_config.worker_count {
            http_server = http_server.workers(worker_count);
        }

        if !http_config.insecure_http {
            let tls_server = http_server
                .bind_openssl(
                    &http_config.sockets[..],
                    crate::http::tls_config(&http_config)
                        .map_err(|e| Error::HTTPSFailed { source: e })?,
                )
                .map_err(|e| Error::HTTPSFailed { source: e.into() })?;

            return Ok(tls_server.run());
        }

        Ok(http_server
            .bind(&http_config.sockets[..])
            .map_err(|e| Error::HTTPFailed { source: e.into() })?
            .run())
    }
}

/// APIs
pub(crate) async fn api(
    request: HttpRequest,
    body: web::Bytes,
    core: web::Data<ApiServer>,
    path: web::Path<String>,
    query: Query<HashMap<String, String>>,
) -> Result<HttpResponse> {
    let path = path.into_inner();
    let path_parts = path.split('/').collect::<Vec<&str>>();
    if path_parts.is_empty() {
        return Err(Error::InvalidRequestPath {
            path: path.to_string(),
        });
    }

    // path looks like `plugin/.../<END>`
    // the index 0 of the path parts is the plugin
    // the rest of the path parts is the resource path
    // if the path parts is equal to 1, return an empty vector
    let plugin = path_parts[0];

    let resource_path = match &path_parts[..] {
        [_, rest @ ..] => rest,
        _ => &[],
    };

    let query = query.into_inner();
    let policy_data = json!(
        {
            "plugin": plugin,
            "resource-path":resource_path,
            "query": query,
        }
    );

    let policy_data_str = policy_data.to_string();
    match plugin {
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
            core.admin.validate_admin_token(&request)?;
            core.attestation_service.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        #[cfg(feature = "as")]
        // Reference value querying API is exposed as
        // GET /reference-value/<reference_value_id>
        "reference-value" if request.method() == Method::GET => {
            core.admin.validate_admin_token(&request)?;
            let reference_value_id = resource_path.join("/");
            let reference_values = core
                .attestation_service
                .query_reference_value(&reference_value_id)
                .await
                .map_err(|e| Error::RvpsError {
                    message: format!("Failed to get reference_values: {e}").to_string(),
                })?;

            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(reference_values))
        }
        #[cfg(feature = "as")]
        "reference-value" if request.method() == Method::POST => {
            core.admin.validate_admin_token(&request)?;
            let message = std::str::from_utf8(&body).map_err(|_| Error::RvpsError {
                message: "Failed to parse reference value message".to_string(),
            })?;
            serde_json::to_string(
                &core
                    .attestation_service
                    .register_reference_value(message)
                    .await
                    .map_err(|e| Error::RvpsError {
                        message: format!("Failed to register reference value: {e}").to_string(),
                    })?,
            )?;

            Ok(HttpResponse::Ok().content_type("application/json").finish())
        }

        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::POST => {
            core.admin.validate_admin_token(&request)?;
            let request: serde_json::Value =
                serde_json::from_slice(&body).map_err(|_| Error::ParsePolicyError {
                    source: anyhow::anyhow!("Illegal SetPolicy Request Json"),
                })?;

            let policy_b64 = request
                .pointer("/policy")
                .ok_or(Error::ParsePolicyError {
                    source: anyhow::anyhow!("No `policy` field inside SetPolicy Request Json"),
                })?
                .as_str()
                .ok_or(Error::ParsePolicyError {
                    source: anyhow::anyhow!(
                        "`policy` field is not a string in SetPolicy Request Json"
                    ),
                })?;

            let policy_slice = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(policy_b64)
                .map_err(|e| Error::ParsePolicyError {
                    source: anyhow::anyhow!("Failed to decode policy: {e}"),
                })?;

            let policy = String::from_utf8(policy_slice).map_err(|e| Error::ParsePolicyError {
                source: anyhow::anyhow!("Failed to decode policy: {e}"),
            })?;

            core.policy_engine
                .set_policy("resource-policy", &policy, true)
                .await?;

            Ok(HttpResponse::Ok().finish())
        }
        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::GET => {
            core.admin.validate_admin_token(&request)?;
            let policy = core.policy_engine.list_policies().await?;

            Ok(HttpResponse::Ok()
                .content_type("application/json")
                .body(serde_json::to_string(&policy)?))
        }
        // If the base_path cannot be served by any of the above built-in
        // functions, try fulfilling the request via the PluginManager.
        plugin_name => {
            let plugin = core
                .plugin_manager
                .get(plugin_name)
                .ok_or(Error::PluginNotFound {
                    plugin_name: plugin_name.to_string(),
                })?;

            let body = body.to_vec();
            if plugin
                .validate_auth(&body, &query, resource_path, request.method())
                .await
                .map_err(|e| Error::PluginInternalError { source: e })?
            {
                // Plugin calls need to be authorized by the admin auth
                core.admin.validate_admin_token(&request)?;
                let response = plugin
                    .handle(&body, &query, resource_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?;

                Ok(HttpResponse::Ok().content_type("text/xml").body(response))
            } else {
                // Plugin calls need to be authorized by the Token and policy
                let token = core
                    .get_attestation_token(&request)
                    .await
                    .map_err(|_| Error::TokenNotFound)?;

                let claims = core.token_verifier.verify(token).await?;

                let claim_str = serde_json::to_string(&claims)?;

                KBS_POLICY_EVALS.inc();

                // TODO: add policy filter support for other plugins
                if !core
                    .policy_engine
                    .evaluate_rego(
                        Some(&policy_data_str),
                        &claim_str,
                        "resource-policy",
                        vec!["data.policy.allow"],
                        vec![],
                    )
                    .await
                    .inspect_err(|_| KBS_POLICY_ERRORS.inc())?
                    .eval_rules_result
                    .get("data.policy.allow")
                    .expect("`data.policy.allow` rule not put as parameter found")
                    .as_ref()
                    .unwrap_or_else(|| {
                        warn!("The KBS Resource Policy does not define the `data.policy.result` rule, use false as default");
                        KBS_POLICY_ERRORS.inc();
                        &serde_json::Value::Bool(false)
                    })
                    .as_bool()
                    .unwrap_or_else(|| {
                        warn!("`data.policy.result` rule result is not a boolean, use false as default");
                        KBS_POLICY_ERRORS.inc();
                        false
                    })
                {
                    KBS_POLICY_VIOLATIONS.inc();
                    return Err(Error::PolicyDeny);
                }
                KBS_POLICY_APPROVALS.inc();

                let response = plugin
                    .handle(&body, &query, resource_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?;
                if plugin
                    .encrypted(&body, &query, resource_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?
                {
                    let public_key = core.token_verifier.extract_tee_public_key(claims)?;
                    let jwe =
                        jwe(public_key, response).map_err(|e| Error::JweError { source: e })?;
                    let res = serde_json::to_string(&jwe)?;
                    return Ok(HttpResponse::Ok()
                        .content_type("application/json")
                        .body(res));
                }

                Ok(HttpResponse::Ok().content_type("text/xml").body(response))
            }
        }
    }
}

pub(crate) async fn prometheus_metrics_handler(
    _request: HttpRequest,
    _core: web::Data<ApiServer>,
) -> Result<HttpResponse> {
    let report =
        crate::prometheus::export_metrics().map_err(|e| Error::PrometheusError { source: e })?;
    Ok(HttpResponse::Ok().body(report))
}

use actix_web::body::MessageBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::middleware::Next;

async fn prometheus_metrics_middleware(
    req: ServiceRequest,
    next: Next<impl MessageBody>,
) -> std::result::Result<ServiceResponse<impl MessageBody>, actix_web::Error> {
    let start = actix::clock::Instant::now();

    // Ignore requests like /metrics for metrics collection, they can make
    // metrics weirdly not add up and distort metrics in odd ways.  They
    // arguably are not very interesting either to a user of KBS metrics.
    let is_kbs_req = req.request().path().starts_with("/kbs");
    if is_kbs_req {
        ACTIVE_CONNECTIONS.inc();
        REQUEST_TOTAL.inc();

        // Consider requests lacking a "content-length" header to be of zero
        // size as this seems to be the usual case with KBS.  (Streamed
        // requests would also lack "content-length" but they don't seem too
        // relevant with KBS.)
        if let Some(len) = req.headers().get("content-length") {
            if let Ok(Ok(len)) = len.to_str().map(|l| l.parse::<u64>()) {
                REQUEST_SIZES.observe(len as f64);
            }
        } else {
            REQUEST_SIZES.observe(0_f64);
        }
    }

    // This is the actual request handling.
    let res = next.call(req).await?;

    if is_kbs_req {
        REQUEST_DURATION.observe(start.elapsed().as_secs_f64());

        if let actix_web::body::BodySize::Sized(len) = res.response().body().size() {
            REQUEST_SIZES.observe(len as f64);
        }

        ACTIVE_CONNECTIONS.dec();
    }

    Ok(res)
}
