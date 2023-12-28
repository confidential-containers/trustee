// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie,
};
use anyhow::{bail, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kbs_types::{Challenge, Request};
use log::warn;
use rand::{thread_rng, Rng};
use semver::Version;
use uuid::Uuid;

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

fn nonce() -> Result<String> {
    let mut nonce: Vec<u8> = vec![0; 32];

    thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(anyhow::Error::from)?;

    Ok(STANDARD.encode(&nonce))
}

/// Finite State Machine model for RCAR handshake
pub(crate) enum SessionStatus {
    Authed {
        request: Request,
        challenge: Challenge,
        id: String,
        timeout: OffsetDateTime,
    },

    Attested {
        attestation_claims: String,
        id: String,
        timeout: OffsetDateTime,
    },
}

macro_rules! impl_member {
    ($attr: ident, $typ: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::Authed { $attr, .. } => $attr,
                SessionStatus::Attested { $attr, .. } => $attr,
            }
        }
    };
    ($attr: ident, $typ: ident, $branch: ident) => {
        pub fn $attr(&self) -> &$typ {
            match self {
                SessionStatus::$branch { $attr, .. } => $attr,
                _ => panic!("unexpected status"),
            }
        }
    };
}

impl SessionStatus {
    pub fn auth(request: Request, timeout: i64) -> Result<Self> {
        let version = Version::parse(&request.version).map_err(anyhow::Error::from)?;
        if !crate::VERSION_REQ.matches(&version) {
            bail!("Invalid Request version {}", request.version);
        }
        let id = Uuid::new_v4().as_simple().to_string();

        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout);

        Ok(Self::Authed {
            request,
            challenge: Challenge {
                nonce: nonce()?,
                extra_params: String::new(),
            },
            id,
            timeout,
        })
    }

    pub fn cookie<'a>(&self) -> Cookie<'a> {
        match self {
            SessionStatus::Authed { id, timeout, .. } => Cookie::build(KBS_SESSION_ID, id.clone())
                .expires(*timeout)
                .finish(),
            SessionStatus::Attested { id, timeout, .. } => {
                Cookie::build(KBS_SESSION_ID, id.clone())
                    .expires(*timeout)
                    .finish()
            }
        }
    }

    impl_member!(request, Request, Authed);
    impl_member!(challenge, Challenge, Authed);
    impl_member!(id, str);
    impl_member!(timeout, OffsetDateTime);

    pub fn is_expired(&self) -> bool {
        return *self.timeout() < OffsetDateTime::now_utc();
    }

    pub fn attest(&mut self, attestation_claims: String) {
        match self {
            SessionStatus::Authed { id, timeout, .. } => {
                *self = SessionStatus::Attested {
                    attestation_claims,
                    id: id.clone(),
                    timeout: *timeout,
                };
            }
            SessionStatus::Attested { .. } => {
                warn!("session already attested.");
            }
        }
    }
}

pub(crate) struct SessionMap {
    pub sessions: scc::HashMap<String, SessionStatus>,
}

impl SessionMap {
    pub fn new() -> Self {
        SessionMap {
            sessions: scc::HashMap::new(),
        }
    }

    pub fn insert(&self, session: SessionStatus) {
        let _ = self.sessions.insert(session.id().to_string(), session);
    }
}
