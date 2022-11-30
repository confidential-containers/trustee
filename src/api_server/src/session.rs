// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use attestation_service::types::AttestationResults;
use kbs_types::{Request, Tee};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use uuid::Uuid;

static SESSION_TIMEOUT: u64 = 5 * 60;

pub(crate) struct Session {
    id: String,
    tee: Tee,
    tee_extra_params: Option<String>,
    attestation_results: Option<AttestationResults>,
    expires_on: Instant,
}

impl Session {
    pub fn from_request(req: &Request) -> Self {
        let id = Uuid::new_v4().as_simple().to_string();
        let tee_extra_params = if req.extra_params.is_empty() {
            None
        } else {
            Some(req.extra_params.clone())
        };

        Session {
            id,
            tee: req.tee.clone(),
            tee_extra_params,
            attestation_results: None,
            expires_on: Instant::now() + Duration::from_secs(SESSION_TIMEOUT),
        }
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn is_authenticated(&self) -> bool {
        self.attestation_results
            .as_ref()
            .map_or(false, |a| a.allow())
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() > self.expires_on
    }

    pub fn is_valid(&self) -> bool {
        self.is_authenticated() && !self.is_expired()
    }
}

pub(crate) struct SessionMap {
    pub sessions: RwLock<HashMap<String, Arc<Mutex<Session>>>>,
}

impl SessionMap {
    pub fn new() -> Self {
        SessionMap {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}
