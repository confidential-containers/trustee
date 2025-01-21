// Copyright (c) 2024 by IBM.
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
    rvps::{RvpsConfig, RvpsCrateConfig},
    token::{ear_broker, simple, AttestationTokenConfig},
};

use anyhow::{bail, Result};
use log::info;
use openssl::pkey::PKey;
use rstest::rstest;
use serial_test::serial;
use std::io::Write;
use tempfile::{NamedTempFile, TempDir};

const KBS_URL: &str = "http://127.0.0.1:8080";
const SECRET_BYTES: &[u8; 8] = b"shhhhhhh";
const SECRET_PATH: &str = "default/test/secret";
const WAIT_TIME: u64 = 3000;

const ALLOW_ALL_POLICY: &str = "
    package policy
    allow = true
";

const DENY_ALL_POLICY: &str = "
    package policy
    allow = false
";

enum PolicyType {
    AllowAll,
    DenyAll,
    //Custom(String),
}

// Parameters that define test behavior (coming from rstest)
struct TestParameters {
    attestation_token_type: String,
}

// Internal state of tests
struct TestHarness {
    kbs_config: KbsConfig,
    auth_privkey: String,

    // Future tests will use some parameters at runtime
    _test_parameters: TestParameters,
}

impl TestHarness {
    fn new(test_parameters: TestParameters) -> Result<TestHarness> {
        let auth_keypair = PKey::generate_ed25519()?;
        let auth_pubkey = String::from_utf8(auth_keypair.public_key_to_pem()?)?;
        let auth_privkey = String::from_utf8(auth_keypair.private_key_to_pem_pkcs8()?)?;

        let work_dir = TempDir::new()?;
        let resource_dir = TempDir::new()?;
        let policy_path = NamedTempFile::new()?;

        let mut auth_pubkey_path = NamedTempFile::new()?;
        auth_pubkey_path.write(auth_pubkey.as_bytes())?;

        let attestation_token_config = match &test_parameters.attestation_token_type[..] {
            "Ear" => AttestationTokenConfig::Ear(ear_broker::Configuration {
                duration_min: 5,
                ..Default::default()
            }),
            "Simple" => AttestationTokenConfig::Simple(simple::Configuration::default()),
            _ => bail!("Unknown attestation token type. Must be Simple or Ear"),
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
                    rvps_config: RvpsConfig::BuiltIn(RvpsCrateConfig::default()),
                    attestation_token_broker: attestation_token_config,
                }),
                timeout: 5,
            },
            http_server: HttpServerConfig {
                sockets: vec!["127.0.0.1:8080".parse()?],
                private_key: None,
                certificate: None,
                insecure_http: true,
            },
            admin: AdminConfig {
                auth_public_key: None,
                insecure_api: true,
            },
            policy_engine: PolicyEngineConfig {
                policy_path: policy_path.path().to_path_buf(),
            },
            plugins: vec![PluginsConfig::ResourceStorage(RepositoryConfig::LocalFs(
                LocalFsRepoDesc {
                    dir_path: resource_dir.path().to_str().unwrap().to_string(),
                },
            ))],
        };

        Ok(TestHarness {
            kbs_config,
            auth_privkey,
            _test_parameters: test_parameters,
        })
    }

    async fn set_policy(&self, policy: PolicyType) -> Result<()> {
        info!("TEST: Setting Resource Policy");

        let policy_bytes = match policy {
            PolicyType::AllowAll => ALLOW_ALL_POLICY.as_bytes().to_vec(),
            PolicyType::DenyAll => DENY_ALL_POLICY.as_bytes().to_vec(),
            //PolicyType::Custom(p) => p.into_bytes(),
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

    async fn set_secret(&self, secret_path: String, secret_bytes: Vec<u8>) -> Result<()> {
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

    async fn get_secret(&self, secret_path: String) -> Result<Vec<u8>> {
        info!("TEST: Getting Secret");
        let resource_bytes =
            kbs_client::get_resource_with_attestation(KBS_URL, &secret_path, None, vec![]).await?;

        Ok(resource_bytes)
    }

    async fn wait(&self) {
        let duration = tokio::time::Duration::from_millis(WAIT_TIME);
        tokio::time::sleep(duration).await;
    }
}

#[rstest]
#[case::ear_allow_all(TestParameters{attestation_token_type: "Ear".to_string() })]
#[case::simple_allow_all(TestParameters{attestation_token_type: "Simple".to_string() })]
#[serial]
#[actix_rt::test]
async fn get_secret_allow_all(#[case] test_parameters: TestParameters) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));
    let harness = TestHarness::new(test_parameters)?;

    let api_server = ApiServer::new(harness.kbs_config.clone()).await?;

    let kbs_server = api_server.server()?;
    let kbs_handle = kbs_server.handle();

    actix_web::rt::spawn(kbs_server);

    harness.wait().await;
    harness.set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;
    harness.set_policy(PolicyType::AllowAll).await?;

    let secret = harness.get_secret(SECRET_PATH.to_string()).await?;

    assert_eq!(secret, SECRET_BYTES);
    info!("TEST: test completed succesfully");

    kbs_handle.stop(true).await;

    Ok(())
}

#[rstest]
#[case::ear_deny_all(TestParameters{attestation_token_type: "Ear".to_string() })]
#[case::simple_deny_all(TestParameters{attestation_token_type: "Simple".to_string() })]
#[serial]
#[actix_rt::test]
async fn get_secret_deny_all(#[case] test_parameters: TestParameters) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));
    let harness = TestHarness::new(test_parameters)?;

    let api_server = ApiServer::new(harness.kbs_config.clone()).await?;

    let kbs_server = api_server.server()?;
    let kbs_handle = kbs_server.handle();

    actix_web::rt::spawn(kbs_server);

    harness.wait().await;
    harness.set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;
    harness.set_policy(PolicyType::DenyAll).await?;

    let secret = harness.get_secret(SECRET_PATH.to_string()).await;

    assert!(secret.is_err());
    assert_eq!(secret.unwrap_err().to_string(), "request unauthorized".to_string());
    info!("TEST: test completed succesfully");

    kbs_handle.stop(true).await;

    Ok(())
}
