// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{RvpsApi, TeeClaims};
use anyhow::*;
use serde::Deserialize;
use shadow_rs::concatcp;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use strum::Display;

use crate::config::DEFAULT_WORK_DIR;

pub mod ear_broker;
pub mod simple;

pub const DEFAULT_TOKEN_DURATION: i64 = 5;
pub const COCO_AS_ISSUER_NAME: &str = "CoCo-Attestation-Service";

const DEFAULT_TOKEN_WORK_DIR: &str = concatcp!(DEFAULT_WORK_DIR, "/token");

#[async_trait::async_trait]
pub trait AttestationTokenBroker: Send + Sync {
    /// Issue an signed attestation token with custom claims.
    /// Return base64 encoded Json Web Token.
    async fn issue(
        &self,
        tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_data_map: HashMap<String, serde_json::Value>,
    ) -> Result<String>;

    async fn set_policy(&self, _policy_id: String, _policy: String) -> Result<()> {
        bail!("Set Policy not support")
    }

    async fn list_policies(&self) -> Result<HashMap<String, String>> {
        bail!("List Policies not support")
    }

    async fn get_policy(&self, _policy_id: String) -> Result<String> {
        bail!("Get Policy not support")
    }
}

#[derive(Deserialize, Debug, Clone, Display, PartialEq)]
#[serde(tag = "type")]
pub enum AttestationTokenConfig {
    Simple(simple::Configuration),
    Ear(ear_broker::Configuration),
}

impl Default for AttestationTokenConfig {
    fn default() -> Self {
        AttestationTokenConfig::Ear(ear_broker::Configuration::default())
    }
}

impl AttestationTokenConfig {
    pub fn to_token_broker(
        &self,
        rvps: Arc<Mutex<dyn RvpsApi + Send + Sync>>,
    ) -> Result<Box<dyn AttestationTokenBroker + Send + Sync>> {
        match self {
            AttestationTokenConfig::Simple(cfg) => Ok(Box::new(
                simple::SimpleAttestationTokenBroker::new(cfg.clone(), rvps)?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
            AttestationTokenConfig::Ear(cfg) => Ok(Box::new(
                ear_broker::EarAttestationTokenBroker::new(cfg.clone(), rvps)?,
            )
                as Box<dyn AttestationTokenBroker + Send + Sync>),
        }
    }
}
