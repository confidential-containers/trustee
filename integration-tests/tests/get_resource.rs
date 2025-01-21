// Copyright (c) 2024 by IBM.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs::ApiServer;

use anyhow::Result;
use log::info;
use rstest::rstest;
use serial_test::serial;

extern crate integration_tests;
use crate::integration_tests::common::{PolicyType, TestHarness, TestParameters};

const SECRET_BYTES: &[u8; 8] = b"shhhhhhh";
const SECRET_PATH: &str = "default/test/secret";

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
