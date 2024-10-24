// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use config::AdminConfig;
use jwt_simple::{
    claims::NoCustomClaims,
    common::VerificationOptions,
    prelude::{Ed25519PublicKey, EdDSAPublicKeyLike},
};

pub mod config;
pub mod error;
pub use error::*;
use log::warn;

#[derive(Default, Clone)]
pub struct Admin {
    public_key: Option<Ed25519PublicKey>,
}

impl TryFrom<AdminConfig> for Admin {
    type Error = Error;

    fn try_from(value: AdminConfig) -> Result<Self> {
        if value.insecure_api {
            warn!("insecure admin APIs are enabled");
            return Ok(Admin::default());
        }

        let key_path = value.auth_public_key.ok_or(Error::NoPublicKeyGiven)?;
        let user_public_key_pem = std::fs::read_to_string(key_path)?;
        let key = Ed25519PublicKey::from_pem(&user_public_key_pem)?;
        Ok(Self {
            public_key: Some(key),
        })
    }
}

impl Admin {
    pub(crate) fn validate_auth(&self, request: &HttpRequest) -> Result<()> {
        let Some(public_key) = &self.public_key else {
            return Ok(());
        };

        let bearer = Authorization::<Bearer>::parse(request)?.into_scheme();

        let token = bearer.token();

        let _claims = public_key
            .verify_token::<NoCustomClaims>(token, Some(VerificationOptions::default()))
            .map_err(|e| Error::JwtVerificationFailed { source: e })?;

        Ok(())
    }
}
