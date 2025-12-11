// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This is a sample to implement a client plugin

use std::collections::HashMap;

use actix_web::http::Method;
use anyhow::Result;
use serde::Deserialize;

use super::super::plugin_manager::ClientPlugin;

#[derive(Deserialize, Clone, Debug, PartialEq)]
pub struct SampleConfig {
    pub item: String,
}

pub struct Sample {
    _item: String,
}

impl TryFrom<SampleConfig> for Sample {
    type Error = anyhow::Error;

    fn try_from(value: SampleConfig) -> anyhow::Result<Self> {
        Ok(Self { _item: value.item })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for Sample {
    async fn handle(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<Vec<u8>> {
        Ok("sample plugin response".as_bytes().to_vec())
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }
}
