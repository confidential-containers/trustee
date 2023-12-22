// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie, Expiration,
};
use anyhow::{anyhow, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kbs_types::{Request, Tee, TeePubKey};
use rand::{thread_rng, Rng};
use semver::Version;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

fn nonce() -> Result<String> {
    let mut nonce: Vec<u8> = vec![0; 32];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(STANDARD.encode(&nonce))
}

#[allow(dead_code)]
pub(crate) struct Session<'a> {
    cookie: Cookie<'a>,
    nonce: String,
    tee: Tee,
    tee_extra_params: Option<String>,
    tee_pub_key: Option<TeePubKey>,
    authenticated: bool,
    attestation_claims: Option<String>,
}

#[allow(dead_code)]
impl<'a> Session<'a> {
    pub fn from_request(req: &Request, timeout: i64) -> Result<Self> {
        let version = Version::parse(&req.version).map_err(anyhow::Error::from)?;
        if !crate::VERSION_REQ.matches(&version) {
            return Err(anyhow!("Invalid Request version {}", req.version));
        }
        let id = Uuid::new_v4().as_simple().to_string();
        let tee_extra_params = if req.extra_params.is_empty() {
            None
        } else {
            Some(req.extra_params.clone())
        };

        let cookie = Cookie::build(KBS_SESSION_ID, id)
            .expires(OffsetDateTime::now_utc() + Duration::minutes(timeout))
            .finish();

        Ok(Session {
            cookie,
            nonce: nonce()?,
            tee: req.tee,
            tee_extra_params,
            tee_pub_key: None,
            authenticated: false,
            attestation_claims: None,
        })
    }

    pub fn id(&self) -> &str {
        self.cookie.value()
    }

    pub fn cookie(&self) -> Cookie {
        self.cookie.clone()
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn tee(&self) -> Tee {
        self.tee
    }

    pub fn tee_public_key(&self) -> Option<TeePubKey> {
        self.tee_pub_key.clone()
    }

    pub fn attestation_claims(&self) -> Option<String> {
        self.attestation_claims.clone()
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    pub fn set_authenticated(&mut self) {
        self.authenticated = true
    }

    pub fn is_expired(&self) -> bool {
        if let Some(Expiration::DateTime(time)) = self.cookie.expires() {
            return OffsetDateTime::now_utc() > time;
        }

        false
    }

    pub fn is_valid(&self) -> bool {
        self.is_authenticated() && !self.is_expired()
    }

    pub fn set_tee_public_key(&mut self, key: TeePubKey) {
        self.tee_pub_key = Some(key)
    }

    pub fn set_attestation_claims(&mut self, claims: String) {
        self.attestation_claims = Some(claims)
    }
}

pub(crate) struct SessionMap<'a> {
    pub sessions: RwLock<HashMap<String, Arc<Mutex<Session<'a>>>>>,
}

impl<'a> SessionMap<'a> {
    pub fn new() -> Self {
        SessionMap {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}
