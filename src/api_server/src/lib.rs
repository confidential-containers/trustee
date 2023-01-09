// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS API server

extern crate actix_web;
extern crate anyhow;
extern crate attestation_service;
extern crate base64;
extern crate env_logger;
extern crate kbs_types;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate rand;
extern crate uuid;

use actix_web::{middleware, web, App, HttpServer};
use anyhow::Result;
use attestation_service::AttestationService;
use config::Config;
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use std::net::SocketAddr;
use std::sync::Arc;

use crate::session::SessionMap;

/// KBS config
pub mod config;

mod http;
mod resource;
mod session;

static KBS_PREFIX: &str = "/kbs";
static KBS_MAJOR_VERSION: u64 = 0;
static KBS_MINOR_VERSION: u64 = 1;
static KBS_PATCH_VERSION: u64 = 0;

lazy_static! {
    static ref VERSION_REQ: VersionReq = {
        let kbs_version = Version {
            major: KBS_MAJOR_VERSION,
            minor: KBS_MINOR_VERSION,
            patch: KBS_PATCH_VERSION,
            pre: Prerelease::EMPTY,
            build: BuildMetadata::EMPTY,
        };

        VersionReq::parse(&format!("<={kbs_version}")).unwrap()
    };
}

macro_rules! kbs_path {
    ($path:expr) => {
        format!("{}/v{}/{}", KBS_PREFIX, KBS_MAJOR_VERSION, $path)
    };
}

/// The KBS API server
pub struct ApiServer {
    config: Config,
    sockets: Vec<SocketAddr>,
    attestation_service: Arc<AttestationService>,
    http_timeout: i64,
}

impl ApiServer {
    /// Create a new KBS HTTP server
    pub fn new(
        config: Config,
        sockets: Vec<SocketAddr>,
        attestation_service: Arc<AttestationService>,
        http_timeout: i64,
    ) -> Self {
        ApiServer {
            config,
            sockets,
            attestation_service,
            http_timeout,
        }
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(&self) -> Result<()> {
        log::info!("Starting HTTP server at {:?}", self.sockets);

        let attestation_service = web::Data::new(self.attestation_service.clone());
        let sessions = web::Data::new(SessionMap::new());
        let http_timeout = self.http_timeout;

        let repository = self
            .config
            .repository_type
            .to_repository(&self.config.repository_description)?;

        HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::default())
                .app_data(web::Data::clone(&sessions))
                .app_data(web::Data::clone(&attestation_service))
                .app_data(web::Data::new(repository.clone()))
                .app_data(web::Data::new(http_timeout))
                .service(web::resource(kbs_path!("auth")).route(web::post().to(http::auth)))
                .service(web::resource(kbs_path!("attest")).route(web::post().to(http::attest)))
                .service(
                    web::resource([
                        kbs_path!("resource/{repository}/{type}/{tag}"),
                        kbs_path!("resource/{type}/{tag}"),
                    ])
                    .route(web::get().to(http::resource)),
                )
        })
        .bind(&self.sockets[..])?
        .run()
        .await
        .map_err(anyhow::Error::from)
    }
}
