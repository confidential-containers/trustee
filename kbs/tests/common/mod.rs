// Copyright (c) 2025 by IBM.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs::admin::config::AdminConfig;
use kbs::attestation::config::{AttestationConfig, AttestationServiceConfig};
use kbs::config::HttpServerConfig;
use kbs::config::KbsConfig;
use kbs::policy_engine::PolicyEngineConfig;
use kbs::token::AttestationTokenVerifierConfig;
use kbs::ApiServer;

use kbs::plugins::{
    implementations::{resource::local_fs::LocalFsRepoDesc, RepositoryConfig},
    PluginsConfig,
};

use attestation_service::{
    config::Config,
    rvps::{grpc::RvpsRemoteConfig, RvpsConfig, RvpsCrateConfig},
    token::{ear_broker, simple, AttestationTokenConfig},
};

use reference_value_provider_service::client as rvps_client;
use reference_value_provider_service::config::Config as RVPSConfig;
use reference_value_provider_service::rvps_api::reference::reference_value_provider_service_server::ReferenceValueProviderServiceServer;
use reference_value_provider_service::storage::{local_json, ReferenceValueStorageConfig};
use reference_value_provider_service::{server::RvpsServer, Rvps};

use anyhow::{anyhow, bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use log::info;
use openssl::pkey::PKey;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tonic::transport::Server;

const KBS_URL: &str = "http://127.0.0.1:8080";
const RVPS_URL: &str = "http://127.0.0.1:50003";
const WAIT_TIME: u64 = 3000;

const ALLOW_ALL_POLICY: &str = "
    package policy
    allow = true
";

const DENY_ALL_POLICY: &str = "
    package policy
    allow = false
";

pub enum PolicyType {
    AllowAll,
    DenyAll,
    Custom(String),
}

pub enum RvpsType {
    Builtin,
    Remote,
}

// Parameters that define test behavior (coming from rstest)
pub struct TestParameters {
    pub attestation_token_type: String,
    pub rvps_type: RvpsType,
}

// Internal state of tests
pub struct TestHarness {
    // This variable is not used thus added an underscore.
    _kbs_config: KbsConfig,
    auth_privkey: String,
    kbs_server_handle: actix_web::dev::ServerHandle,
    _work_dir: TempDir,

    // Future tests will use some parameters at runtime
    _test_parameters: TestParameters,
}

impl TestHarness {
    pub async fn new(test_parameters: TestParameters) -> Result<TestHarness> {
        let auth_keypair = PKey::generate_ed25519()?;
        let auth_pubkey = String::from_utf8(auth_keypair.public_key_to_pem()?)?;
        let auth_privkey = String::from_utf8(auth_keypair.private_key_to_pem_pkcs8()?)?;

        let work_dir = TempDir::new()?;
        let resource_dir = work_dir
            .path()
            .join("resources")
            .into_os_string()
            .into_string()
            .map_err(|e| anyhow!("Failed to join resource path: {:?}", e))?;
        let as_policy_dir = work_dir
            .path()
            .join("as_policy")
            .into_os_string()
            .into_string()
            .map_err(|e| anyhow!("Failed to join as_policy path: {:?}", e))?;
        let kbs_policy_path = work_dir.path().join("kbs_policy");
        let rv_path = work_dir
            .path()
            .join("reference_values")
            .into_os_string()
            .into_string()
            .map_err(|e| anyhow!("Failed to join reference values path: {:?}", e))?;
        let auth_pubkey_path = work_dir.path().join("auth_pubkey");

        tokio::fs::write(auth_pubkey_path, auth_pubkey.as_bytes()).await?;

        let attestation_token_config = match &test_parameters.attestation_token_type[..] {
            "Ear" => AttestationTokenConfig::Ear(ear_broker::Configuration {
                duration_min: 5,
                policy_dir: as_policy_dir,
                ..Default::default()
            }),
            "Simple" => AttestationTokenConfig::Simple(simple::Configuration {
                policy_dir: as_policy_dir,
                ..Default::default()
            }),
            _ => bail!("Unknown attestation token type. Must be Simple or Ear"),
        };

        // Setup RVPS either remotely or builtin
        let rvps_config = match &test_parameters.rvps_type {
            RvpsType::Builtin => RvpsConfig::BuiltIn(RvpsCrateConfig {
                storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
                    file_path: rv_path,
                }),
                ..Default::default()
            }),
            RvpsType::Remote => {
                info!("Starting Remote RVPS");
                let service = Rvps::new(RVPSConfig {
                    storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
                        file_path: rv_path,
                    }),
                    ..Default::default()
                })?;
                let inner = Arc::new(RwLock::new(service));
                let rvps_server = RvpsServer::new(inner.clone());

                let rvps_future = Server::builder()
                    .add_service(ReferenceValueProviderServiceServer::new(rvps_server))
                    .serve("127.0.0.1:50003".parse()?);

                tokio::spawn(rvps_future);

                RvpsConfig::GrpcRemote(RvpsRemoteConfig {
                    address: RVPS_URL.to_string(),
                })
            }
        };

        let kbs_config = KbsConfig {
            attestation_token: AttestationTokenVerifierConfig {
                trusted_certs_paths: vec![],
                insecure_key: true,
                trusted_jwk_sets: vec![],
                extra_teekey_paths: vec![],
            },
            attestation_service: AttestationConfig {
                attestation_service: AttestationServiceConfig::CoCoASBuiltIn(Config {
                    work_dir: work_dir.path().to_path_buf(),
                    rvps_config,
                    attestation_token_broker: attestation_token_config,
                }),
                timeout: 5,
            },
            http_server: HttpServerConfig {
                sockets: vec!["127.0.0.1:8080".parse()?],
                private_key: None,
                certificate: None,
                insecure_http: true,
                payload_request_size: 2,
            },
            admin: AdminConfig {
                auth_public_key: None,
                insecure_api: true,
            },
            policy_engine: PolicyEngineConfig {
                policy_path: kbs_policy_path,
            },
            plugins: vec![PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
                LocalFsRepoDesc {
                    dir_path: resource_dir,
                },
            ))],
        };
        // Spawn the KBS Server
        let api_server = ApiServer::new(kbs_config.clone()).await?;

        let kbs_server = api_server.server()?;
        let kbs_handle = kbs_server.handle();

        tokio::spawn(kbs_server);

        Ok(TestHarness {
            _kbs_config: kbs_config,
            auth_privkey,
            kbs_server_handle: kbs_handle,
            _work_dir: work_dir,
            _test_parameters: test_parameters,
        })
    }

    pub async fn cleanup(&self) -> Result<()> {
        self.kbs_server_handle.stop(true).await;

        Ok(())
    }

    pub async fn set_policy(&self, policy: PolicyType) -> Result<()> {
        info!("TEST: Setting Resource Policy");

        let policy_bytes = match policy {
            PolicyType::AllowAll => ALLOW_ALL_POLICY.as_bytes().to_vec(),
            PolicyType::DenyAll => DENY_ALL_POLICY.as_bytes().to_vec(),
            PolicyType::Custom(p) => p.into_bytes(),
        };

        kbs_client::set_resource_policy(
            KBS_URL,
            self.auth_privkey.clone(),
            policy_bytes,
            // Optional HTTPS certs for KBS
            vec![],
        )
        .await?;

        Ok(())
    }

    pub async fn set_secret(&self, secret_path: String, secret_bytes: Vec<u8>) -> Result<()> {
        info!("TEST: Setting Secret");
        kbs_client::set_resource(
            KBS_URL,
            self.auth_privkey.clone(),
            secret_bytes,
            &secret_path,
            // Optional HTTPS certs for KBS
            vec![],
        )
        .await?;

        Ok(())
    }

    pub async fn get_secret(&self, secret_path: String) -> Result<Vec<u8>> {
        info!("TEST: Getting Secret");
        let resource_bytes =
            kbs_client::get_resource_with_attestation(KBS_URL, &secret_path, None, vec![]).await?;

        Ok(resource_bytes)
    }

    pub async fn wait(&self) {
        let duration = tokio::time::Duration::from_millis(WAIT_TIME);
        tokio::time::sleep(duration).await;
    }

    pub async fn set_reference_value(&self, key: String, value: String) -> Result<()> {
        let provenance = json!({key: [value]}).to_string();
        let provenance = STANDARD.encode(provenance);

        let message = json!({
            "version": "0.1.0",
            "type": "sample",
            "payload": provenance
        });

        rvps_client::register(RVPS_URL.to_string(), message.to_string()).await?;

        Ok(())
    }
}
