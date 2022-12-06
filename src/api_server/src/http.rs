// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpResponse};
use kbs_types::{Challenge, Request};
use std::sync::{Arc, Mutex};

use crate::session::{Session, SessionMap};

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap<'_>>,
) -> HttpResponse {
    log::info!("request: {:?}", &request);

    let session = match Session::from_request(&request) {
        Ok(s) => s,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .message_body(BoxBody::new(format!("{}", err)))
                .unwrap();
        }
    };
    let response = HttpResponse::Ok().cookie(session.cookie()).json(Challenge {
        nonce: session.nonce().to_string(),
        extra_params: "".to_string(),
    });

    map.sessions
        .write()
        .unwrap()
        .insert(session.id().to_string(), Arc::new(Mutex::new(session)));

    response
}
