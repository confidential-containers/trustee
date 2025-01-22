// Copyright (c) 2024 by IBM.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use log::info;
use rstest::rstest;
use serial_test::serial;

const SECRET_BYTES: &[u8; 8] = b"shhhhhhh";
const SECRET_PATH: &str = "default/test/secret";

mod common;

use common::{PolicyType, RvpsType, TestHarness, TestParameters};

#[rstest]
#[case::ear_allow_all(TestParameters{attestation_token_type: "Ear".to_string(), rvps_type: RvpsType::Builtin }, "allow_all".to_string())]
#[case::simple_allow_all(TestParameters{attestation_token_type: "Simple".to_string(), rvps_type: RvpsType::Builtin }, "allow_all".to_string())]
#[case::ear_deny_all(TestParameters{attestation_token_type: "Ear".to_string(), rvps_type: RvpsType::Builtin }, "deny_all".to_string())]
#[case::simple_deny_all(TestParameters{attestation_token_type: "Simple".to_string(), rvps_type: RvpsType::Builtin }, "deny_all".to_string())]
#[case::contraindicated(TestParameters{attestation_token_type: "Ear".to_string(), rvps_type: RvpsType::Builtin }, "contraindicated".to_string())]
#[case::not_contraindicated(TestParameters{attestation_token_type: "Ear".to_string(), rvps_type: RvpsType::Remote }, "not_contraindicated".to_string())]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn run_test(
    #[case] test_parameters: TestParameters,
    #[case] test_type: String,
) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let harness = TestHarness::new(test_parameters).await?;

    let test_result = match test_type.as_str() {
        "allow_all" => get_secret_allow_all(&harness).await,
        "deny_all" => get_secret_deny_all(&harness).await,
        "contraindicated" => get_secret_contraindicated(&harness).await,
        "not_contraindicated" => get_secret_not_contraindicated(&harness).await,
        _ => bail!("unkown test case"),
    };

    harness.cleanup().await?;
    test_result
}

async fn get_secret_allow_all(harness: &TestHarness) -> Result<()> {
    harness.wait().await;
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;
    harness.set_policy(PolicyType::AllowAll).await?;

    let secret = harness.get_secret(SECRET_PATH.to_string()).await?;

    assert_eq!(secret, SECRET_BYTES);
    info!("TEST: test completed successfully");

    Ok(())
}

async fn get_secret_deny_all(harness: &TestHarness) -> Result<()> {
    harness.wait().await;
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;
    harness.set_policy(PolicyType::DenyAll).await?;

    let secret = harness.get_secret(SECRET_PATH.to_string()).await;

    assert!(secret.is_err());
    assert_eq!(
        secret.unwrap_err().to_string(),
        "request unauthorized".to_string()
    );
    info!("TEST: test completed successfully");

    Ok(())
}

const CHECK_CONTRAINDICATED_POLICY: &str = "
package policy
import rego.v1

default allow = false

allow if {
    input[\"submods\"][\"cpu\"][\"ear.status\"] != \"contraindicated\"
}
";

async fn get_secret_contraindicated(harness: &TestHarness) -> Result<()> {
    harness.wait().await;
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;
    harness
        .set_policy(PolicyType::Custom(CHECK_CONTRAINDICATED_POLICY.to_string()))
        .await?;

    let secret = harness.get_secret(SECRET_PATH.to_string()).await;

    assert!(secret.is_err());
    assert_eq!(
        secret.unwrap_err().to_string(),
        "request unauthorized".to_string()
    );
    info!("TEST: test completed succesfully");

    Ok(())
}

async fn get_secret_not_contraindicated(harness: &TestHarness) -> Result<()> {
    harness.wait().await;
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;
    harness
        .set_policy(PolicyType::Custom(CHECK_CONTRAINDICATED_POLICY.to_string()))
        .await?;

    // so this test will fail if run in an enclave.
    harness
        .set_reference_value("svn".to_string(), "1".to_string())
        .await?;
    harness
        .set_reference_value("launch_digest".to_string(), "abcde".to_string())
        .await?;

    let secret = harness.get_secret(SECRET_PATH.to_string()).await?;

    assert_eq!(secret, SECRET_BYTES);
    info!("TEST: test completed succesfully");

    Ok(())
}
