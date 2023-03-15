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
use anyhow::{anyhow, bail, Result};
use attestation_service::AttestationService;
use config::Config;
use rustls::{server::ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, read_one, Item};
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    private_key: Option<PathBuf>,
    certificate: Option<PathBuf>,
    insecure: bool,
    attestation_service: Arc<AttestationService>,
    http_timeout: i64,
}

impl ApiServer {
    /// Create a new KBS HTTP server
    pub fn new(
        config: Config,
        sockets: Vec<SocketAddr>,
        private_key: Option<PathBuf>,
        certificate: Option<PathBuf>,
        insecure: bool,
        attestation_service: Arc<AttestationService>,
        http_timeout: i64,
    ) -> Result<Self> {
        if !insecure && (private_key.is_none() || certificate.is_none()) {
            bail!("Missing HTTPS credentials");
        }

        Ok(ApiServer {
            config,
            sockets,
            private_key,
            certificate,
            insecure,
            attestation_service,
            http_timeout,
        })
    }

    fn tls_config(&self) -> Result<ServerConfig> {
        let cert_file = &mut BufReader::new(File::open(
            self.certificate
                .clone()
                .ok_or(anyhow!("Missing certificate"))?,
        )?);

        let key_file = &mut BufReader::new(File::open(
            self.private_key
                .clone()
                .ok_or(anyhow!("Missing private key"))?,
        )?);

        let cert_chain = certs(cert_file)?
            .iter()
            .map(|c| Certificate(c.clone()))
            .collect();

        let key = match read_one(key_file)? {
            Some(Item::RSAKey(key)) | Some(Item::PKCS8Key(key)) | Some(Item::ECKey(key)) => {
                Ok(PrivateKey(key))
            }
            None | Some(_) => Err(anyhow!("Invalid private key file")),
        }?;

        ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(anyhow::Error::from)
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(&self) -> Result<()> {
        log::info!(
            "Starting HTTP{} server at {:?}",
            if !self.insecure { "S" } else { "" },
            self.sockets
        );

        let attestation_service = web::Data::new(self.attestation_service.clone());
        let sessions = web::Data::new(SessionMap::new());
        let http_timeout = self.http_timeout;

        let repository = self
            .config
            .repository_type
            .to_repository(&self.config.repository_description)?;

        let http_server = HttpServer::new(move || {
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
                    .route(web::get().to(http::get_resource)),
                )
        });

        if !self.insecure {
            let tls_config = self.tls_config()?;
            http_server
                .bind_rustls(&self.sockets[..], tls_config)?
                .run()
                .await
                .map_err(anyhow::Error::from)
        } else {
            http_server
                .bind(&self.sockets[..])?
                .run()
                .await
                .map_err(anyhow::Error::from)
        }
    }
}
