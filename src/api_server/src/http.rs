// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpResponse};
use anyhow::Result;
use kbs_types::{Challenge, Request};
use rand::{thread_rng, Rng};
use std::sync::{Arc, Mutex};

use crate::session::{Session, SessionMap};

fn nonce() -> Result<String> {
    let mut nonce: Vec<u8> = vec![0; 32];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(base64::encode_config(&nonce, base64::STANDARD))
}

/// POST /auth
pub(crate) async fn auth(
    request: web::Json<Request>,
    map: web::Data<SessionMap<'_>>,
) -> HttpResponse {
    log::info!("request: {:?}", &request);

    let nonce = match nonce() {
        Ok(n) => n,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .message_body(BoxBody::new(format!("{}", err)))
                .unwrap();
        }
    };

    let session = Session::from_request(&request);
    let response = HttpResponse::Ok().cookie(session.cookie()).json(Challenge {
        nonce,
        extra_params: "".to_string(),
    });

    map.sessions
        .write()
        .unwrap()
        .insert(session.id().to_string(), Arc::new(Mutex::new(session)));

    response
}
