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

use crate::session::SessionMap;

mod http;
mod session;

/// Start the HTTP server and serve API requests.
pub async fn serve() -> Result<()> {
    log::info!("starting HTTP server at http://localhost:8080");

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .app_data(web::Data::new(SessionMap::new()))
            .service(web::resource("/auth").route(web::post().to(http::auth)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
    .map_err(anyhow::Error::from)
}
