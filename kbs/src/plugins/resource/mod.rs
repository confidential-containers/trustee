// Copyright (c) 2024 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

pub mod local_fs;

#[cfg(feature = "aliyun")]
pub mod aliyun_kms;

pub mod error;

use actix_web::http::Method;
pub use error::*;

pub mod backend;
pub use backend::*;

use super::{plugin_manager::ClientPlugin, Result};

#[async_trait::async_trait]
impl ClientPlugin for ResourceStorage {
    async fn handle(
        &self,
        body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let resource_desc = path
            .strip_prefix('/')
            .ok_or(ResourceError::IllegalAccessedPath { path: path.into() })?;
        match method.as_str() {
            "POST" => {
                let resource_description = ResourceDesc::try_from(resource_desc)?;
                self.set_secret_resource(resource_description, body).await?;
                Ok(vec![])
            }
            "GET" => {
                let resource_description = ResourceDesc::try_from(resource_desc)?;
                let resource = self.get_secret_resource(resource_description).await?;

                Ok(resource)
            }
            _ => Err(ResourceError::IllegalHttpMethod)?,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "POST" {
            return Ok(true);
        }

        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        if method.as_str() == "GET" {
            return Ok(true);
        }

        Ok(false)
    }
}
