// Copyright (c) 2025 by IBM.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs::admin::{
    password::{PasswordAdminConfig, PasswordPersona},
    simple::{SimpleAdminConfig, SimplePersonaConfig},
    AdminBackendType, AdminConfig,
};
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
    ear_token::EarTokenConfiguration,
    rvps::{grpc::RvpsRemoteConfig, RvpsConfig, RvpsCrateConfig},
};

use reference_value_provider_service::client as rvps_client;
use reference_value_provider_service::config::Config as RVPSConfig;
use reference_value_provider_service::rvps_api::reference::reference_value_provider_service_server::ReferenceValueProviderServiceServer;
use reference_value_provider_service::storage::{local_json, ReferenceValueStorageConfig};
use reference_value_provider_service::{server::RvpsServer, Rvps};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use jwt_simple::algorithms::EdDSAKeyPairLike;
use jwt_simple::prelude::{Claims, Duration, Ed25519KeyPair};
use log::info;
use serde_json::json;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::RwLock;
use tonic::transport::Server;

const KBS_URL: &str = "http://127.0.0.1:8081";
const RVPS_URL: &str = "http://127.0.0.1:51003";
const WAIT_TIME: u64 = 10000;

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
    Custom(&'static str),
}

pub enum RvpsType {
    Builtin,
    Remote,
}

pub enum AdminType {
    DenyAll,
    Simple,
    Password,
}

/// An enum that selects between TestParameter configurations
/// so that TestParameters can be reused between tests.
#[derive(PartialEq, Clone)]
pub enum KbsConfigType {
    EarTokenBuiltInRvps,
    EarTokenBuiltInRvpsDenyAllAdmin,
    EarTokenBuiltInRvpsPasswordAdmin,
    EarTokenRemoteRvps,
}

/// The KbsConfigType enum can be turned into TestParameters
impl From<KbsConfigType> for TestParameters {
    fn from(val: KbsConfigType) -> Self {
        match val {
            KbsConfigType::EarTokenBuiltInRvps => TestParameters {
                rvps_type: RvpsType::Builtin,
                admin_type: AdminType::Simple,
            },
            KbsConfigType::EarTokenRemoteRvps => TestParameters {
                rvps_type: RvpsType::Remote,
                admin_type: AdminType::Simple,
            },
            KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin => TestParameters {
                rvps_type: RvpsType::Builtin,
                admin_type: AdminType::DenyAll,
            },
            KbsConfigType::EarTokenBuiltInRvpsPasswordAdmin => TestParameters {
                rvps_type: RvpsType::Builtin,
                admin_type: AdminType::Password,
            },
        }
    }
}

/// Parameters that define test behavior
pub struct TestParameters {
    pub rvps_type: RvpsType,
    pub admin_type: AdminType,
}

/// Internal state of tests
pub struct TestHarness {
    pub kbs_config: KbsConfig,
    pub admin_token: Option<String>,
    kbs_server_handle: actix_web::dev::ServerHandle,
    _work_dir: TempDir,

    // Future tests will use some parameters at runtime
    _test_parameters: TestParameters,
}

impl TestHarness {
    pub async fn new(test_parameters: TestParameters) -> Result<TestHarness> {
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

        let attestation_token_config = EarTokenConfiguration {
            policy_dir: as_policy_dir,
            ..Default::default()
        };

        // Setup RVPS either remotely or builtin
        let rvps_config = match &test_parameters.rvps_type {
            RvpsType::Builtin => RvpsConfig::BuiltIn(RvpsCrateConfig {
                extractors: None,
                storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
                    file_path: rv_path,
                }),
            }),
            RvpsType::Remote => {
                info!("Starting Remote RVPS");
                let service = Rvps::new(RVPSConfig {
                    extractors: None,
                    storage: ReferenceValueStorageConfig::LocalJson(local_json::Config {
                        file_path: rv_path,
                    }),
                })?;
                let inner = Arc::new(RwLock::new(service));
                let rvps_server = RvpsServer::new(inner.clone());

                let rvps_future = Server::builder()
                    .add_service(ReferenceValueProviderServiceServer::new(rvps_server))
                    .serve("127.0.0.1:51003".parse()?);

                tokio::spawn(rvps_future);

                RvpsConfig::GrpcRemote(RvpsRemoteConfig {
                    address: RVPS_URL.to_string(),
                })
            }
        };

        let admin_token = match &test_parameters.admin_type {
            AdminType::Simple => {
                let admin_key_pair = Ed25519KeyPair::generate();
                let auth_pubkey = admin_key_pair.public_key().to_pem();

                tokio::fs::write(auth_pubkey_path.clone(), auth_pubkey.as_bytes()).await?;

                let claims = Claims::create(Duration::from_hours(2));
                Some(admin_key_pair.sign(claims)?)
            }
            _ => None,
        };

        let admin_config = match &test_parameters.admin_type {
            AdminType::Simple => AdminConfig {
                admin_backend: AdminBackendType::Simple(SimpleAdminConfig {
                    personas: vec![SimplePersonaConfig {
                        id: "tester".to_string(),
                        public_key_path: auth_pubkey_path.as_path().to_path_buf(),
                    }],
                }),
            },
            AdminType::DenyAll => AdminConfig {
                admin_backend: AdminBackendType::DenyAll,
            },
            AdminType::Password => AdminConfig {
                admin_backend: AdminBackendType::Password(PasswordAdminConfig {
                    personas: vec![PasswordPersona {
                        username: "test1".to_string(),
                        // "password1" 
                        password_hash: "$argon2id$v=19$m=16,t=2,p=1$YWJjZGVmZ2g$1QKfKpovkKZdJMxz+ZBVfw".to_string()
                    },
                    PasswordPersona {
                        username: "test2".to_string(),
                        // "password2"
                        password_hash: "$argon2id$v=19$m=16,t=2,p=1$YWJjZGVhbGtqYXNsZGtmamFsa2o$HO5wN6BOZ9l3o3tzO8ks2w".to_string(),
                    }],
                    admin_token_life_hours: 2,
                    key_pair_path: None,
                }),
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
                    verifier_config: None,
                }),
                timeout: 5,
            },
            http_server: HttpServerConfig {
                sockets: vec!["127.0.0.1:8081".parse()?],
                private_key: None,
                certificate: None,
                insecure_http: true,
                payload_request_size: 2,
                worker_count: Some(4),
            
            },
            admin: admin_config,
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
            kbs_config,
            admin_token,
            kbs_server_handle: kbs_handle,
            _work_dir: work_dir,
            _test_parameters: test_parameters,
        })
    }

    pub async fn cleanup(&self) -> Result<()> {
        self.kbs_server_handle.stop(true).await;

        Ok(())
    }

    pub async fn login(&mut self, username: String, password: String) -> Result<()> {
        let token =
            kbs_client::admin_login(KBS_URL.to_string(), username, password, vec![]).await?;

        self.admin_token = Some(token);

        Ok(())
    }

    pub fn replace_admin_token(&mut self) -> Result<()> {
        let admin_key_pair = Ed25519KeyPair::generate();

        let claims = Claims::create(Duration::from_hours(2));
        self.admin_token = Some(admin_key_pair.sign(claims)?);

        Ok(())
    }

    pub async fn set_policy(&self, policy: PolicyType) -> Result<()> {
        info!("TEST: Setting Resource Policy");

        let policy_bytes = match policy {
            PolicyType::AllowAll => ALLOW_ALL_POLICY.as_bytes().to_vec(),
            PolicyType::DenyAll => DENY_ALL_POLICY.as_bytes().to_vec(),
            PolicyType::Custom(p) => p.to_string().into_bytes(),
        };

        kbs_client::set_resource_policy(
            KBS_URL,
            self.admin_token
                .clone()
                .ok_or(anyhow!("Auth Token not found."))?,
            policy_bytes,
            // Optional HTTPS certs for KBS
            vec![],
        )
        .await?;

        Ok(())
    }

    pub async fn set_attestation_policy(&self, policy: String, policy_id: String) -> Result<()> {
        kbs_client::set_attestation_policy(
            KBS_URL,
            self.admin_token
                .clone()
                .ok_or(anyhow!("Auth token not found."))?,
            policy.as_bytes().to_vec(),
            None, // Policy type (default is rego)
            Some(policy_id),
            vec![], // Optional HTTPS certs for KBS
        )
        .await?;

        Ok(())
    }

    pub async fn set_secret(&self, secret_path: String, secret_bytes: Vec<u8>) -> Result<()> {
        info!("TEST: Setting Secret");
        kbs_client::set_resource(
            KBS_URL,
            self.admin_token
                .clone()
                .ok_or(anyhow!("Auth token not found."))?,
            secret_bytes,
            &secret_path,
            // Optional HTTPS certs for KBS
            vec![],
        )
        .await?;

        Ok(())
    }

    pub async fn get_secret(
        &self,
        secret_path: String,
        init_data: Option<String>,
    ) -> Result<Vec<u8>> {
        info!("TEST: Getting Secret");
        let resource_bytes = kbs_client::get_resource_with_attestation(
            KBS_URL,
            &secret_path,
            None,
            vec![],
            init_data,
        )
        .await?;

        Ok(resource_bytes)
    }

    pub async fn wait(&self) {
        let duration = tokio::time::Duration::from_millis(WAIT_TIME);
        tokio::time::sleep(duration).await;
    }

    pub async fn set_reference_value(&self, key: String, value: serde_json::Value) -> Result<()> {
        let provenance = json!({key: value}).to_string();
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
