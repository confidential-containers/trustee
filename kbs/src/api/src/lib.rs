// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS API server

#![allow(clippy::too_many_arguments)]

extern crate actix_web;
extern crate anyhow;
extern crate base64;
extern crate env_logger;
extern crate kbs_types;
#[macro_use]
extern crate lazy_static;
extern crate log;
extern crate rand;
extern crate uuid;

use actix_web::{middleware, web, App, HttpServer};
use anyhow::{anyhow, bail, Context, Result};
#[cfg(feature = "as")]
use attestation::AttestationService;
use jwt_simple::prelude::Ed25519PublicKey;
#[cfg(feature = "resource")]
use resource::RepositoryConfig;
use semver::{BuildMetadata, Prerelease, Version, VersionReq};
use std::net::SocketAddr;
use std::path::PathBuf;
#[cfg(feature = "resource")]
use token::AttestationTokenVerifierType;

#[cfg(feature = "rustls")]
use rustls::ServerConfig;

#[cfg(feature = "openssl")]
use openssl::ssl::SslAcceptorBuilder;

#[cfg(feature = "as")]
use crate::session::SessionMap;

#[cfg(feature = "policy")]
use crate::policy_engine::{PolicyEngine, PolicyEngineConfig};

#[cfg(feature = "as")]
/// Attestation Service
pub mod attestation;

#[allow(unused_imports)]
/// KBS config
pub mod config;

mod auth;
#[allow(unused_imports)]
mod http;

#[cfg(feature = "resource")]
mod resource;

#[cfg(feature = "as")]
mod session;

#[cfg(feature = "resource")]
mod token;

#[cfg(feature = "policy")]
/// Resource Policy Engine
pub mod policy_engine;

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

#[allow(dead_code)]
/// The KBS API server
pub struct ApiServer {
    sockets: Vec<SocketAddr>,
    private_key: Option<PathBuf>,
    /// This user public key is used to verify the jwt.
    /// The jwt is carried with the POST request for
    /// resource registration
    user_public_key: Option<PathBuf>,
    certificate: Option<PathBuf>,
    insecure: bool,

    #[cfg(feature = "as")]
    attestation_service: AttestationService,

    http_timeout: i64,
    insecure_api: bool,
    #[cfg(feature = "resource")]
    repository_config: RepositoryConfig,
    #[cfg(feature = "resource")]
    attestation_token_type: AttestationTokenVerifierType,
    #[cfg(feature = "policy")]
    policy_engine_config: PolicyEngineConfig,
}

impl ApiServer {
    /// Create a new KBS HTTP server
    pub fn new(
        sockets: Vec<SocketAddr>,
        private_key: Option<PathBuf>,
        user_public_key: Option<PathBuf>,
        certificate: Option<PathBuf>,
        insecure: bool,

        #[cfg(feature = "as")] attestation_service: &AttestationService,

        http_timeout: i64,
        insecure_api: bool,
        #[cfg(feature = "resource")] repository_config: RepositoryConfig,
        #[cfg(feature = "resource")] attestation_token_type: AttestationTokenVerifierType,
        #[cfg(feature = "policy")] policy_engine_config: PolicyEngineConfig,
    ) -> Result<Self> {
        if !insecure && (private_key.is_none() || certificate.is_none()) {
            bail!("Missing HTTPS credentials");
        }

        cfg_if::cfg_if! {
            if #[cfg(not(any(feature = "as", feature = "resource")))] {
                compile_error!("Must enable at least one of the following features: `as`, `resource`");
            }
        }

        Ok(ApiServer {
            sockets,
            private_key,
            user_public_key,
            certificate,
            insecure,

            #[cfg(feature = "as")]
            attestation_service: attestation_service.clone(),

            http_timeout,
            insecure_api,
            #[cfg(feature = "resource")]
            repository_config,
            #[cfg(feature = "resource")]
            attestation_token_type,
            #[cfg(feature = "policy")]
            policy_engine_config,
        })
    }

    #[cfg(feature = "rustls")]
    fn tls_config(&self) -> Result<ServerConfig> {
        use rustls::{Certificate, PrivateKey};
        use rustls_pemfile::{certs, read_one, Item};
        use std::fs::File;
        use std::io::BufReader;

        let cert_file = &mut BufReader::new(File::open(
            self.certificate
                .clone()
                .ok_or_else(|| anyhow!("Missing certificate"))?,
        )?);

        let key_file = &mut BufReader::new(File::open(
            self.private_key
                .clone()
                .ok_or_else(|| anyhow!("Missing private key"))?,
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

    #[cfg(feature = "openssl")]
    fn tls_config(&self) -> Result<SslAcceptorBuilder> {
        use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};

        let cert_file = self
            .certificate
            .clone()
            .ok_or_else(|| anyhow!("Missing certificate"))?;

        let key_file = self
            .private_key
            .clone()
            .ok_or_else(|| anyhow!("Missing private key"))?;

        let mut builder = SslAcceptor::mozilla_modern(SslMethod::tls())?;
        builder.set_private_key_file(key_file, SslFiletype::PEM)?;
        builder.set_certificate_chain_file(cert_file)?;

        Ok(builder)
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(&self) -> Result<()> {
        log::info!(
            "Starting HTTP{} server at {:?}",
            if !self.insecure { "S" } else { "" },
            self.sockets
        );

        #[cfg(feature = "as")]
        let attestation_service = web::Data::new(self.attestation_service.clone());

        #[cfg(feature = "as")]
        let sessions = web::Data::new(SessionMap::new());

        let http_timeout = self.http_timeout;

        #[cfg(feature = "resource")]
        let repository = self.repository_config.initialize()?;

        #[cfg(feature = "resource")]
        let token_verifier = self.attestation_token_type.to_token_verifier()?;

        #[cfg(feature = "policy")]
        let policy_engine = PolicyEngine::new(&self.policy_engine_config).await?;

        let user_public_key = match self.insecure_api {
            true => None,
            false => match &self.user_public_key {
                Some(key_path) => {
                    let user_public_key_pem = tokio::fs::read_to_string(key_path)
                        .await
                        .context("read user public key")?;
                    let key = Ed25519PublicKey::from_pem(&user_public_key_pem)
                        .context("parse user public key")?;
                    Some(key)
                }
                None => bail!("no user public key given"),
            },
        };

        let insecure_api = self.insecure_api;

        let http_server = HttpServer::new(move || {
            #[allow(unused_mut)]
            let mut server_app = App::new()
                .wrap(middleware::Logger::default())
                .app_data(web::Data::new(http_timeout))
                .app_data(web::Data::new(user_public_key.clone()))
                .app_data(web::Data::new(insecure_api));

            cfg_if::cfg_if! {
                if #[cfg(feature = "as")] {
                    server_app = server_app.app_data(web::Data::clone(&sessions))
                    .app_data(web::Data::clone(&attestation_service)).service(web::resource(kbs_path!("auth")).route(web::post().to(http::auth)))
                    .service(web::resource(kbs_path!("attest")).route(web::post().to(http::attest)))
                    .service(
                        web::resource(kbs_path!("attestation-policy"))
                            .route(web::post().to(http::attestation_policy)),
                    );
            }}
            cfg_if::cfg_if! {
                if #[cfg(feature = "resource")] {
                    server_app = server_app.app_data(web::Data::new(repository.clone()))
                    .app_data(web::Data::new(token_verifier.clone()))
                    .service(
                        web::resource([
                            kbs_path!("resource/{repository}/{type}/{tag}"),
                            kbs_path!("resource/{type}/{tag}"),
                        ])
                        .route(web::get().to(http::get_resource))
                        .route(web::post().to(http::set_resource)),
                    );
                }
            }
            cfg_if::cfg_if! {
                if #[cfg(feature = "policy")] {
                    server_app = server_app.app_data(web::Data::new(policy_engine.clone()))
                    .service(
                        web::resource(kbs_path!("resource-policy")).route(web::post().to(http::resource_policy)),
                    );
                }
            }
            server_app
        });

        if !self.insecure {
            let tls_server = {
                cfg_if::cfg_if! {
                    if #[cfg(feature = "openssl")] {
                        http_server.bind_openssl(&self.sockets[..], self.tls_config()?)?
                    } else {
                        http_server.bind_rustls(&self.sockets[..], self.tls_config()?)?
                    }
                }
            };

            tls_server.run().await.map_err(anyhow::Error::from)
        } else {
            http_server
                .bind(&self.sockets[..])?
                .run()
                .await
                .map_err(anyhow::Error::from)
        }
    }
}
