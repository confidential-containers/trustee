// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This is a sample to implement a client plugin

use actix_web::{http::Method, HttpResponse};
use serde::Deserialize;

use super::{plugin_manager::ClientPlugin, Result};

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
        _body: Vec<u8>,
        _query: String,
        _path: String,
        _method: &Method,
    ) -> Result<HttpResponse> {
        let response = HttpResponse::Ok().body("sample plugin response");
        Ok(response)
    }
}
