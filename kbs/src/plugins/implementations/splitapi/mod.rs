// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! Splitapi plugin provisions credential resources for a sandbox and sends
//! sever specific credentials to the sandbox to initiate Split API proxy
//! server and establish a secure tunnel between tenant and the API proxy
//! server.

pub mod manager;
pub mod mapper;
pub mod generator;

use actix_web::http::Method;
use anyhow::{anyhow, Error, bail, Result};

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
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method**. Only supports `GET`")
        }

        match path {
            "credential" => {
                let params: SandboxParams =
                serde_qs::from_str(query).map_err(|e| {
                    anyhow!("Failed to parse query string: {}", e)
                })?;
                let credential = self.backend.get_server_credential(&params).await?;

                Ok(credential)
            }
            _ => Err(Error::msg("Illegal format of the request"))
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
        Ok(false)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio;
    use std::sync::Arc;
    use std::{
        fs,
        path::{PathBuf},
    };
    use anyhow::Context;

    use super::generator::{CA_CRT_FILENAME, SERVER_KEY_FILENAME, SERVER_CRT_FILENAME};
    use super::generator::ServerCredential;


    #[tokio::test]
    async fn test_handle() {
        // Arrange: create an instance of `SplitAPI`
        let desc = manager::SplitAPIRepoDesc::default();
        let backend = manager::CertManager::new(&desc);
        let backend = Arc::new(backend.expect("Failed to initialize backend"));
        let split_api = SplitAPI { backend: backend };
        
        // Define sample inputs
        let body: &[u8] = b"";
        let query = "id=3367348&ip=60.11.12.43&name=pod7";
        let path = "credential";
        let method = &Method::GET;

        // Act: call the handle method
        let result = split_api.handle(body, query, path, method).await;

        println!("plugin dir = {}", desc.plugin_dir);

        // Assert: check the result
        match result {
            Ok(response) => {

                // Expected results
                let sandbox_dir = PathBuf::from(&desc.plugin_dir)
                    .as_path()
                    .join("pod7_60.11.12.43_3367348");
                
                let server_key = sandbox_dir.as_path().join(SERVER_KEY_FILENAME);
                let server_crt = sandbox_dir.as_path().join(SERVER_CRT_FILENAME);
                let ca_crt = sandbox_dir.as_path().join(CA_CRT_FILENAME);

                let resource = ServerCredential {
                    key: fs::read(server_key.as_path())
                        .with_context(|| format!("read {}", server_key.display()))
                        .expect("failed to read server key"),
                    crt: fs::read(server_crt.as_path())
                        .with_context(|| format!("read {}", server_crt.display()))
                        .expect("failed to read server crt"),
                    ca_crt: fs::read(ca_crt.as_path())
                        .with_context(|| format!("read {}", ca_crt.display()))
                        .expect("failed to read ca crt"),
                };

                let expected_response = serde_json::to_vec(&resource).unwrap();
                assert_eq!(response, expected_response);
            }
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    }
}