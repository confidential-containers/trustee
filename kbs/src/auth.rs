// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::http::header::Header;
use actix_web::HttpRequest;
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use anyhow::{Context, Result};
use jwt_simple::prelude::{
    Ed25519PublicKey, EdDSAPublicKeyLike, NoCustomClaims, VerificationOptions,
};

pub(crate) fn validate_auth(request: &HttpRequest, public_key: &Ed25519PublicKey) -> Result<()> {
    let bearer = Authorization::<Bearer>::parse(request)
        .context("parse Authorization header failed")?
        .into_scheme();

    let token = bearer.token();

    let _claims = public_key
        .verify_token::<NoCustomClaims>(token, Some(VerificationOptions::default()))
        .context("token verification failed")?;

    Ok(())
}
