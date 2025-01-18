// Copyright (c) 2025 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Splitapi plugin provisions credential resources for a sandbox and sends
//! sever specific credentials to the sandbox to initiate Split API proxy
//! server and establish a secure tunnel between tenant and the API proxy
//! server.

pub mod generator;
pub mod manager;

use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};

pub mod backend;
pub use backend::*;

use super::super::plugin_manager::ClientPlugin;

#[async_trait::async_trait]
impl ClientPlugin for SplitAPI {
    async fn handle(
        &self,
        _body: &[u8],
        query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let sub_path = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with `/`")?;
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method. Only GET is supported");
        }

        match sub_path {
            "credential" => {
                let params = SandboxParams::try_from(query)?;
                let credential = self.backend.get_server_credential(&params).await?;

                Ok(credential)
            }
            _ => Err(anyhow!("{} not supported", sub_path))?,
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(false)
    }

    /// Whether the body needs to be encrypted via TEE key pair.
    /// If returns `Ok(true)`, the KBS server will encrypt the whole body
    /// with TEE key pair and use KBS protocol's Response format.
    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &str,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tokio;

    use super::manager::{Credentials, ServerCredentials};

    #[tokio::test]
    async fn test_handle() {
        let plugin_dir = "/opt/confidential-containers/kbs/plugin/splitapi";
        let config = SplitAPIConfig::default();
        let backend = manager::CertManager::new(
            PathBuf::from(&plugin_dir),
            config.credential_blob_filename,
            &config.certificate_details,
        );
        let backend = Arc::new(backend.expect("Failed to initialize backend"));
        let split_api = SplitAPI {
            backend: backend.clone(),
        };

        // Define sample inputs
        let body: &[u8] = b"";
        let query = "id=3367348&ip=60.11.12.43&name=pod7";
        let path = "/credential";
        let method = &Method::GET;

        // Act: call the handle method
        let result = split_api.handle(body, query, path, method).await;

        // Assert: check the result
        match result {
            Ok(response) => {
                // Expected results
                let key = String::from("pod7_60.11.12.43_3367348");

                let state = backend.state.read().await;
                let credentials: Credentials = state
                    .get(&key)
                    .cloned()
                    .expect("Credentisl not found in hashmap");

                let resource = ServerCredentials {
                    key: credentials.server_key,
                    crt: credentials.server_crt,
                    ca_crt: credentials.ca_crt,
                };

                let expected_response = serde_json::to_vec(&resource).unwrap();
                assert_eq!(response, expected_response);
            }
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    }
}
