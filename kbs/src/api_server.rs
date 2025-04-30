// Copyright (c) 2023 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{
    http::{header::Header, Method},
    middleware, web, App, HttpRequest, HttpResponse, HttpServer,
};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::Context;
use log::{info, warn};

use crate::{
    admin::Admin, config::KbsConfig, jwe::jwe, plugins::PluginManager, policy_engine::PolicyEngine,
    prometheus_exporter, token::TokenVerifier, Error, Result,
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

    #[cfg(feature = "as")]
    attestation_service: crate::attestation::AttestationService,

    policy_engine: PolicyEngine,
    admin_auth: Admin,
    config: KbsConfig,
    token_verifier: TokenVerifier,

    prometheus_metrics: ApiServerMetrics,
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
        let plugin_manager = PluginManager::try_from(config.plugins.clone())
            .map_err(|e| Error::PluginManagerInitialization { source: e })?;
        let token_verifier = TokenVerifier::from_config(config.attestation_token.clone()).await?;
        let policy_engine = PolicyEngine::new(&config.policy_engine).await?;
        let admin_auth = Admin::try_from(config.admin.clone())?;
        let prometheus_metrics = ApiServerMetrics::new()?;

        #[cfg(feature = "as")]
        let attestation_service =
            crate::attestation::AttestationService::new(config.attestation_service.clone()).await?;

        Ok(Self {
            config,
            plugin_manager,
            policy_engine,
            admin_auth,
            token_verifier,

            #[cfg(feature = "as")]
            attestation_service,

            prometheus_metrics,
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
        let http_server = HttpServer::new({
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
                        web::resource([kbs_path!("{base_path}{additional_path:.*}")])
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
) -> Result<HttpResponse> {
    let query = request.query_string();
    let base_path = request
        .match_info()
        .get("base_path")
        .ok_or(Error::InvalidRequestPath {
            path: request.path().to_string(),
        })?;
    let additional_path =
        request
            .match_info()
            .get("additional_path")
            .ok_or(Error::InvalidRequestPath {
                path: request.path().to_string(),
            })?;

    let endpoint = format!("{base_path}{additional_path}");

    match base_path {
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
            core.attestation_service.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::POST => {
            core.admin_auth.validate_auth(&request)?;
            core.policy_engine.set_policy(&body).await?;

            Ok(HttpResponse::Ok().finish())
        }
        // TODO: consider to rename the api name for it is not only for
        // resource retrievement but for all plugins.
        "resource-policy" if request.method() == Method::GET => {
            core.admin_auth.validate_auth(&request)?;
            let policy = core.policy_engine.get_policy().await?;

            Ok(HttpResponse::Ok().content_type("text/xml").body(policy))
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
                .validate_auth(&body, query, additional_path, request.method())
                .await
                .map_err(|e| Error::PluginInternalError { source: e })?
            {
                // Plugin calls need to be authorized by the admin auth
                core.admin_auth.validate_auth(&request)?;
                let response = plugin
                    .handle(&body, query, additional_path, request.method())
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

                // TODO: add policy filter support for other plugins
                if !core.policy_engine.evaluate(&endpoint, &claim_str).await? {
                    return Err(Error::PolicyDeny);
                }

                let response = plugin
                    .handle(&body, query, additional_path, request.method())
                    .await
                    .map_err(|e| Error::PluginInternalError { source: e })?;
                if plugin
                    .encrypted(&body, query, additional_path, request.method())
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
    let report = prometheus_exporter::instance
        .lock()
        .unwrap()
        .export_metrics()
        .map_err(|e| Error::PrometheusError { source: e })?;
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
    let api_server = req
        .request()
        .app_data::<web::Data<ApiServer>>()
        .unwrap()
        .clone();

    // Ignore requests like /metrics for metrics collection, they can make
    // metrics weirdly not add up and distort metrics in odd ways.  They
    // arguably are not very interesting either to a user of KBS metrics.
    let is_kbs_req = req.request().path().starts_with("/kbs");
    if is_kbs_req {
        api_server.prometheus_metrics.requests_total.inc();

        // Consider requests lacking a "content-length" header to be of zero
        // size as this seems to be the usual case with KBS.  (Streamed
        // requests would also lack "content-length" but they don't seem too
        // relevant with KBS.)
        if let Some(len) = req.headers().get("content-length") {
            if let Ok(Ok(len)) = len.to_str().map(|l| l.parse::<u64>()) {
                api_server
                    .prometheus_metrics
                    .request_size
                    .observe(len as f64);
            }
        } else {
            api_server.prometheus_metrics.request_size.observe(0_f64);
        }
    }

    // This is the actual request handling.
    let res = next.call(req).await?;

    if is_kbs_req {
        api_server
            .prometheus_metrics
            .request_duration
            .observe(start.elapsed().as_secs_f64());

        if let actix_web::body::BodySize::Sized(len) = res.response().body().size() {
            api_server
                .prometheus_metrics
                .response_size
                .observe(len as f64);
        }
    }

    Ok(res)
}

#[derive(Clone)]
struct ApiServerMetrics {
    requests_total: prometheus::Counter,
    request_duration: prometheus::Histogram,
    request_size: prometheus::Histogram,
    response_size: prometheus::Histogram,
}

impl ApiServerMetrics {
    fn new() -> std::result::Result<Self, crate::error::Error> {
        let prom = prometheus_exporter::instance.lock().unwrap();
        let requests_total = prometheus::Counter::with_opts(prometheus::Opts::new(
            "http_requests_total",
            "Total HTTP requests count",
        ))?;
        prom.register(Box::new(requests_total.clone()))?;

        let request_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "http_request_duration_seconds",
                "Distribution of request handling duration",
            )
            .buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.5, 1.0]),
        )?;
        prom.register(Box::new(request_duration.clone()))?;

        let request_size = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "http_request_size_bytes",
                "Distribution of request body sizes",
            )
            .buckets(prometheus::exponential_buckets(32.0, 4.0, 5)?),
        )?;
        prom.register(Box::new(request_size.clone()))?;

        let response_size = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "http_response_size_bytes",
                "Distribution of response body sizes",
            )
            .buckets(prometheus::exponential_buckets(32.0, 4.0, 5)?),
        )?;
        prom.register(Box::new(response_size.clone()))?;

        Ok(ApiServerMetrics {
            requests_total,
            request_duration,
            request_size,
            response_size,
        })
    }
}

impl Drop for ApiServerMetrics {
    fn drop(&mut self) {
        let prom = prometheus_exporter::instance.lock().unwrap();

        if let Err(err) = prom.unregister(Box::new(self.requests_total.clone())) {
            warn!("couldn't unregister Prometheus requests_total: {:?}", err);
        }
        if let Err(err) = prom.unregister(Box::new(self.request_duration.clone())) {
            warn!("couldn't unregister Prometheus request_duration: {:?}", err);
        }
        if let Err(err) = prom.unregister(Box::new(self.request_size.clone())) {
            warn!("couldn't unregister Prometheus request_size: {:?}", err);
        }
        if let Err(err) = prom.unregister(Box::new(self.response_size.clone())) {
            warn!("couldn't unregister Prometheus response_size: {:?}", err);
        }
    }
}
