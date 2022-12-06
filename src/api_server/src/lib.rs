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
extern crate log;
extern crate rand;
extern crate uuid;

use actix_web::{middleware, web, App, HttpServer};
use anyhow::Result;
use attestation_service::AttestationService;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::session::SessionMap;

mod http;
mod session;

/// The KBS API server
pub struct ApiServer {
    sockets: Vec<SocketAddr>,
    attestation_service: Arc<AttestationService>,
}

impl ApiServer {
    /// Create a new KBS HTTP server
    pub fn new(sockets: Vec<SocketAddr>, attestation_service: Arc<AttestationService>) -> Self {
        ApiServer {
            sockets,
            attestation_service,
        }
    }

    /// Start the HTTP server and serve API requests.
    pub async fn serve(&self) -> Result<()> {
        log::info!("Starting HTTP server at {:?}", self.sockets);

        let attestation_service = web::Data::new(self.attestation_service.clone());
        let sessions = web::Data::new(SessionMap::new());

        HttpServer::new(move || {
            App::new()
                .wrap(middleware::Logger::default())
                .app_data(web::Data::clone(&sessions))
                .app_data(web::Data::clone(&attestation_service))
                .service(web::resource("/auth").route(web::post().to(http::auth)))
                .service(web::resource("/attest").route(web::post().to(http::attest)))
        })
        .bind(&self.sockets[..])?
        .run()
        .await
        .map_err(anyhow::Error::from)
    }
}
