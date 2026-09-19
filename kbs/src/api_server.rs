// Copyright (c) 2023 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use actix_governor::{
    governor::middleware::NoOpMiddleware, Governor, GovernorConfig, GovernorConfigBuilder,
    PeerIpKeyExtractor,
};
use actix_web::{
    guard,
    http::{header::Header, Method},
    middleware,
    web::{self, Query},
    App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use base64::Engine;
use key_value_storage::StorageProvider;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde_json::json;
use tracing::{info, warn};

use crate::{
    admin::Admin,
    config::{HttpServerConfig, KbsConfig},
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

pub const KBS_STORAGE_NAMESPACE: &str = "kbs";

/// The name of the policy rule that determines if the request is allowed or denied
pub const KBS_POLICY_RULE: &str = "data.policy.allow";

/// The name of the policy identifier for the KBS Resource Policy
pub const KBS_POLICY_ID: &str = "resource-policy";

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

    pub policy_engine: PolicyEngine<Regorus>,
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
        let storage_provider =
            key_value_storage::KvStorageProvider::new(config.storage_backend.clone());
        info!(
            backend_type = ?config.storage_backend.storage_type,
            "KBS storage backend"
        );

        let plugin_manager = PluginManager::new(config.plugins.clone(), storage_provider.clone())
            .await
            .map_err(|e| Error::PluginManagerInitialization { source: e })?;
        let token_verifier = TokenVerifier::from_config(config.attestation_token.clone()).await?;

        let policy_storage_backend = storage_provider
            .get_or_register(KBS_STORAGE_NAMESPACE)
            .await
            .map_err(|e| Error::StorageBackendInitialization { source: e })?;

        let policy_engine = PolicyEngine::new(policy_storage_backend);

        policy_engine
            .set_policy(
                KBS_POLICY_ID,
                include_str!("../sample_policies/default.rego"),
                false,
            )
            .await?;
        let admin = Admin::new(config.admin.clone()).await?;

        #[cfg(feature = "as")]
        let attestation_service = crate::attestation::AttestationService::new(
            config.attestation_service.clone(),
            config.session_storage_type.unwrap_or_else(|| {
                info!(
                    "Session storage type not configured, using storage backend type: {:?}",
                    config.storage_backend.storage_type
                );
                config.storage_backend.storage_type
            }),
            &config.storage_backend,
            storage_provider.clone(),
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
        let auth_rate_limit = auth_rate_limit(&http_config)?;

        #[allow(clippy::redundant_closure)]
        let mut http_server = HttpServer::new({
            move || {
                let api_server = self.clone();
                let auth_rate_limit = auth_rate_limit.clone();
                App::new()
                    .wrap(middleware::Logger::default())
                    .wrap(middleware::from_fn(prometheus_metrics_middleware))
                    .app_data(web::Data::new(api_server))
                    .app_data(web::PayloadConfig::new(
                        (1024 * 1024 * http_config.payload_request_size) as usize,
                    ))
                    .configure(|cfg| configure_kbs_routes(cfg, auth_rate_limit))
                    .service(
                        web::resource("/metrics")
                            .route(web::get().to(prometheus_metrics_handler))
                            .route(web::post().to(|| HttpResponse::MethodNotAllowed())),
                    )
                    .route("/healthz", web::get().to(HttpResponse::Ok))
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

/// Rate limiter for `POST /kbs/v0/auth`, keyed by client IP. The limiter state
/// lives behind an `Arc`, so clones share it across all server workers.
type AuthRateLimit = GovernorConfig<PeerIpKeyExtractor, NoOpMiddleware>;

fn auth_rate_limit(http_config: &HttpServerConfig) -> Result<Option<AuthRateLimit>> {
    if http_config.auth_rate_limit_per_second == 0 {
        return Ok(None);
    }
    GovernorConfigBuilder::default()
        .requests_per_second(http_config.auth_rate_limit_per_second.into())
        .burst_size(http_config.auth_rate_limit_burst)
        .finish()
        .map(Some)
        .ok_or_else(|| Error::HTTPFailed {
            source: anyhow::anyhow!(
                "invalid auth rate limit: {} requests per second with burst {}",
                http_config.auth_rate_limit_per_second,
                http_config.auth_rate_limit_burst
            ),
        })
}

/// Register the KBS API routes.
///
/// With a rate limit configured, `POST /kbs/v0/auth` gets its own resource ahead
/// of the catch-all so it wins route matching, wrapped in the governor middleware
/// but served by the same `api` handler. That handler dispatches on the first
/// path segment, so the resource also covers `/kbs/v0/auth/<anything>`;
/// otherwise a client could sidestep the limit by appending a segment. The POST
/// guard lets other methods fall through to the catch-all unchanged.
fn configure_kbs_routes(cfg: &mut web::ServiceConfig, auth_rate_limit: Option<AuthRateLimit>) {
    if let Some(rate_limit) = auth_rate_limit {
        cfg.service(
            web::resource(kbs_path!("{path:auth(?:/.*)?}"))
                .guard(guard::Post())
                .wrap(Governor::new(&rate_limit))
                .route(web::post().to(api)),
        );
    }
    cfg.service(
        web::resource([kbs_path!("{path:.*}")])
            .route(web::get().to(api))
            .route(web::post().to(api))
            .route(web::put().to(api))
            .route(web::delete().to(api)),
    );
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
            core.admin
                .check_admin_access(&request)
                .map_err(|e| Error::AdminAuthAccess {
                    source: e,
                    endpoint: "attestation-policy".to_string(),
                })?;
            core.attestation_service.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        #[cfg(feature = "as")]
        // Reference value querying API is exposed as
        // GET /reference-value/<reference_value_id>
        "reference-value" if request.method() == Method::GET => {
            core.admin
                .check_admin_access(&request)
                .map_err(|e| Error::AdminAuthAccess {
                    source: e,
                    endpoint: "reference-value".to_string(),
                })?;
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
            core.admin
                .check_admin_access(&request)
                .map_err(|e| Error::AdminAuthAccess {
                    source: e,
                    endpoint: "reference-value".to_string(),
                })?;
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
            core.admin
                .check_admin_access(&request)
                .map_err(|e| Error::AdminAuthAccess {
                    source: e,
                    endpoint: "resource-policy".to_string(),
                })?;
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
                .set_policy(KBS_POLICY_ID, &policy, true)
                .await?;

            Ok(HttpResponse::Ok().finish())
        }
        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::GET => {
            core.admin
                .check_admin_access(&request)
                .map_err(|e| Error::AdminAuthAccess {
                    source: e,
                    endpoint: "resource-policy".to_string(),
                })?;
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
                core.admin.check_admin_access(&request)?;
                let response = plugin
                    .handle(&body, &query, resource_path, request.method(), None)
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?;

                Ok(HttpResponse::Ok().content_type("text/xml").body(response))
            } else {
                // Plugin calls need to be authorized by the Token and policy
                let token = core
                    .get_attestation_token(&request)
                    .await
                    .map_err(|_| Error::TokenNotFound)?;

                let claims = core.token_verifier.verify(token)?;

                let claim_str = serde_json::to_string(&claims)?;

                KBS_POLICY_EVALS.inc();
                // TODO: add policy filter support for other plugins
                if !core
                    .policy_engine
                    .evaluate_rego(
                        Some(policy_data_str),
                        claim_str,
                        KBS_POLICY_ID,
                        vec![KBS_POLICY_RULE.to_string()],
                        vec![],
                    )
                    .await
                    .inspect_err(|_| KBS_POLICY_ERRORS.inc())?
                    .eval_rules_result
                    .get(KBS_POLICY_RULE)
                    .expect("`data.policy.allow` rule not put as parameter found")
                    .as_ref()
                    .unwrap_or_else(|| {
                        warn!("The KBS Resource Policy does not define the `{KBS_POLICY_RULE}` rule, use false as default" );
                        KBS_POLICY_ERRORS.inc();
                        &serde_json::Value::Bool(false)
                    })
                    .as_bool()
                    .unwrap_or_else(|| {
                        warn!("`{KBS_POLICY_RULE}` rule result is not a boolean, use false as default");
                        KBS_POLICY_ERRORS.inc();
                        false
                    })
                {
                    KBS_POLICY_VIOLATIONS.inc();
                    return Err(Error::PolicyDeny);
                }
                KBS_POLICY_APPROVALS.inc();

                let init_data = claims
                    .pointer("/submods/cpu0/ear.veraison.annotated-evidence/init_data_claims");

                let response = plugin
                    .handle(&body, &query, resource_path, request.method(), init_data)
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

#[cfg(all(test, feature = "coco-as-builtin"))]
mod tests {
    use super::*;
    use crate::token::AttestationTokenVerifierConfig;
    use actix_web::http::StatusCode;
    use actix_web::test::{call_service, init_service, TestRequest};
    use std::net::SocketAddr;

    async fn test_api_server(per_second: u32, burst: u32) -> ApiServer {
        let config = KbsConfig {
            attestation_token: AttestationTokenVerifierConfig {
                insecure_header_jwk: true,
                ..Default::default()
            },
            http_server: HttpServerConfig {
                insecure_http: true,
                auth_rate_limit_per_second: per_second,
                auth_rate_limit_burst: burst,
                ..Default::default()
            },
            ..Default::default()
        };
        ApiServer::new(config).await.expect("api server")
    }

    fn post_from(peer: SocketAddr, uri: &str) -> TestRequest {
        TestRequest::post().uri(uri).peer_addr(peer)
    }

    fn auth_body() -> serde_json::Value {
        json!({ "version": "0.4.0", "tee": "sample", "extra-params": {} })
    }

    #[actix_web::test]
    async fn auth_rate_limit_throttles_auth_per_peer() {
        let api_server = test_api_server(1, 2).await;
        let rate_limit = auth_rate_limit(&api_server.config.http_server).unwrap();
        assert!(rate_limit.is_some());
        let app = init_service(
            App::new()
                .app_data(web::Data::new(api_server))
                .configure(|cfg| configure_kbs_routes(cfg, rate_limit)),
        )
        .await;
        let peer: SocketAddr = "10.0.0.1:4000".parse().unwrap();

        // The burst admits two requests; the third from the same peer is rejected.
        for _ in 0..2 {
            let req = post_from(peer, "/kbs/v0/auth")
                .set_json(auth_body())
                .to_request();
            let resp = call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let req = post_from(peer, "/kbs/v0/auth")
            .set_json(auth_body())
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key("retry-after"));

        // A trailing path segment reaches the same handler and shares the budget.
        let req = post_from(peer, "/kbs/v0/auth/extra")
            .set_json(auth_body())
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // Another peer has its own budget.
        let other: SocketAddr = "10.0.0.2:4000".parse().unwrap();
        let req = post_from(other, "/kbs/v0/auth")
            .set_json(auth_body())
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);

        // Other endpoints are not limited: attest from the throttled peer still
        // reaches the handler, which rejects it for lack of a session, not with 429.
        for _ in 0..3 {
            let req = post_from(peer, "/kbs/v0/attest")
                .set_payload("{}")
                .to_request();
            let resp = call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        // Only POST is limited; other methods fall through to the catch-all as before.
        let req = TestRequest::get()
            .uri("/kbs/v0/auth")
            .peer_addr(peer)
            .to_request();
        let resp = call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[actix_web::test]
    async fn auth_rate_limit_disabled_by_default() {
        let api_server = test_api_server(0, 0).await;
        let rate_limit = auth_rate_limit(&api_server.config.http_server).unwrap();
        assert!(rate_limit.is_none());
        let app = init_service(
            App::new()
                .app_data(web::Data::new(api_server))
                .configure(|cfg| configure_kbs_routes(cfg, rate_limit)),
        )
        .await;
        let peer: SocketAddr = "10.0.0.1:4000".parse().unwrap();

        for _ in 0..5 {
            let req = post_from(peer, "/kbs/v0/auth")
                .set_json(auth_body())
                .to_request();
            let resp = call_service(&app, req).await;
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[test]
    fn auth_rate_limit_rejects_zero_burst() {
        let http_config = HttpServerConfig {
            auth_rate_limit_per_second: 1,
            auth_rate_limit_burst: 0,
            ..Default::default()
        };
        assert!(auth_rate_limit(&http_config).is_err());
    }
}
