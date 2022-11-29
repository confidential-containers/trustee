// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! KBS API server

extern crate actix_web;
extern crate anyhow;
extern crate env_logger;
extern crate kbs_types;
extern crate log;

use actix_web::{middleware, web, App, HttpServer};
use anyhow::Result;

mod http;

/// Start the HTTP server and serve API requests.
pub async fn serve() -> Result<()> {
    log::info!("starting HTTP server at http://localhost:8080");

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::Logger::default())
            .service(web::resource("/auth").route(web::post().to(http::auth)))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
    .map_err(anyhow::Error::from)
}
