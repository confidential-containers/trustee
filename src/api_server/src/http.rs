// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{body::BoxBody, web, HttpResponse};
use anyhow::Result;
use kbs_types::{Challenge, Request};
use rand::{thread_rng, Rng};

fn nonce() -> Result<String> {
    let mut nonce: Vec<u8> = vec![0; 32];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(base64::encode_config(&nonce, base64::STANDARD))
}

/// This handler uses json extractor
pub(crate) async fn auth(request: web::Json<Request>) -> HttpResponse {
    log::info!("request: {:?}", &request);

    let nonce = match nonce() {
        Ok(n) => n,
        Err(err) => {
            return HttpResponse::InternalServerError()
                .message_body(BoxBody::new(format!("{}", err)))
                .unwrap();
        }
    };

    HttpResponse::Ok().json(Challenge {
        nonce,
        extra_params: "extra_params".to_string(),
    })
}
