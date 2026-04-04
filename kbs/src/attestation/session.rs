// Copyright (c) 2022 by Rivos Inc.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use actix_web::cookie::{
    time::{Duration, OffsetDateTime},
    Cookie,
};
use anyhow::Result;
use kbs_types::{Challenge, Request};
use key_value_storage::{KeyValueStorage, SetParameters};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

pub(crate) static KBS_SESSION_ID: &str = "kbs-session-id";

/// Finite State Machine model for RCAR handshake
#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) enum SessionStatus {
    Authed {
        request: Request,
        challenge: Challenge,
        id: String,
        #[serde(with = "time::serde::rfc3339")]
        timeout: OffsetDateTime,
    },

    Attested {
        token: String,
        id: String,
        #[serde(with = "time::serde::rfc3339")]
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
    pub fn auth(request: Request, timeout: i64, challenge: Challenge) -> Self {
        let id = Uuid::new_v4().as_simple().to_string();

        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout);

        Self::Authed {
            request,
            challenge,
            id,
            timeout,
        }
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
        *self.timeout() < OffsetDateTime::now_utc()
    }

    pub fn attest(&mut self, token: String) {
        match self {
            SessionStatus::Authed { id, timeout, .. } => {
                *self = SessionStatus::Attested {
                    token,
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

#[derive(Clone)]
pub(crate) struct SessionMap {
    pub storage: Arc<dyn KeyValueStorage>,
}

impl SessionMap {
    pub fn new(storage: Arc<dyn KeyValueStorage>) -> Self {
        SessionMap { storage }
    }

    pub async fn insert(&self, session: SessionStatus) -> Result<()> {
        let session_bytes = serde_json::to_vec(&session)?;
        let session_id = session.id();
        let _ = self
            .storage
            .set(
                session_id,
                &session_bytes,
                SetParameters { overwrite: true },
            )
            .await?;
        Ok(())
    }

    pub async fn get(&self, session_id: &str) -> Result<Option<SessionStatus>> {
        let session_bytes = self.storage.get(session_id).await?;
        let Some(session_bytes) = session_bytes else {
            return Ok(None);
        };
        let session: SessionStatus = serde_json::from_slice(&session_bytes)?;
        if session.is_expired() {
            let _ = self.storage.delete(session_id).await?;
            return Ok(None);
        }
        Ok(Some(session))
    }

    pub async fn cleanup_expired(&self) -> Result<()> {
        let keys = self.storage.list().await?;
        for key in keys {
            let Some(value) = self.storage.get(&key).await? else {
                continue;
            };

            let Ok(session) = serde_json::from_slice::<SessionStatus>(&value) else {
                continue;
            };

            if session.is_expired() {
                let _ = self.storage.delete(&key).await?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use kbs_types::Tee;
    use key_value_storage::memory::MemoryKeyValueStorage;
    use serde_json::json;

    use super::*;

    #[tokio::test]
    async fn test_session_map_insert_and_get() {
        let storage = Arc::new(MemoryKeyValueStorage::default());
        let session_map = SessionMap::new(storage);
        let request = Request {
            version: "1.0.0".to_string(),
            tee: Tee::Sample,
            extra_params: json!({}),
        };
        let challenge = Challenge {
            nonce: "1234567890".to_string(),
            extra_params: json!({}),
        };
        let session = SessionStatus::auth(request, 60, challenge);
        session_map.insert(session.clone()).await.unwrap();
        let session_get = session_map.get(&session.id()).await.unwrap().unwrap();

        // The kbs_types::Challenge and kbs_types::Request does not handle PartialEq
        // so we need to compare the debugging string directly.
        assert_eq!(format!("{session:?}"), format!("{session_get:?}"));
    }
}
