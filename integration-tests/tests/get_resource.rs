// Copyright (c) 2024 by IBM.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};
use log::info;
use rstest::rstest;
use serde_json::{json, Value};
use serial_test::serial;

extern crate integration_tests;
use crate::integration_tests::common::{KbsConfigType, PolicyType, TestHarness};

const SECRET_BYTES: &[u8; 8] = b"shhhhhhh";
const SECRET_PATH: &str = "default/test/secret";

#[rstest]
//
// Simple Tests with AllowAll or DenyAll policies
//
#[case::basic_ear_allow_all(KbsConfigType::EarTokenBuiltInRvps, PolicyType::AllowAll, vec![], false, Result::Ok(SECRET_BYTES))]
#[case::basic_simple_allow_all(KbsConfigType::SimpleTokenBuiltInRvps, PolicyType::AllowAll, vec![], false, Result::Ok(SECRET_BYTES))]
#[case::basic_ear_deny_all(KbsConfigType::EarTokenBuiltInRvps, PolicyType::DenyAll, vec![], false, Result::Err(anyhow!("request unauthorized")))]
#[case::basic_simple_deny_all(KbsConfigType::SimpleTokenBuiltInRvps, PolicyType::DenyAll, vec![], false, Result::Err(anyhow!("request unauthorized")))]
//
// Tests that use a KBS Policy that checks the EAR status
//
#[case::policy_contraindicated(KbsConfigType::EarTokenRemoteRvps, PolicyType::Custom(CHECK_CONTRAINDICATED_POLICY), vec![], false, Result::Err(anyhow!("request unauthorized")))]
#[case::policy_not_contraindicated(KbsConfigType::EarTokenRemoteRvps, PolicyType::Custom(CHECK_CONTRAINDICATED_POLICY), vec![("svn",json!(["1"])),("launch_digest", json!(["abcde"])), ("major_version", 1.into()), ("minimum_minor_version", 1.into())], false, Result::Ok(SECRET_BYTES))]
//
// Tests that use the sample device
//
#[case::device_contraindicated(KbsConfigType::EarTokenRemoteRvps, PolicyType::Custom(CHECK_CONTRAINDICATED_DEVICE_POLICY), vec![("svn",json!(["1"])),    ("launch_digest", json!(["abcde"])), ("major_version", 1.into()), ("minimum_minor_version", 1.into())], true, Result::Err(anyhow!("request unauthorized")))]
#[case::device_not_contraindicated(KbsConfigType::EarTokenRemoteRvps, PolicyType::Custom(CHECK_CONTRAINDICATED_DEVICE_POLICY), vec![("svn",json!(["1"])),("launch_digest", json!(["abcde"])), ("major_version", 1.into()), ("minimum_minor_version", 1.into()), ("device_svn", json!(["2"]))], true, Result::Ok(SECRET_BYTES))]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn run_test(
    #[case] test_parameter_type: KbsConfigType,
    #[case] policy: PolicyType,
    #[case] rvs: Vec<(&str, Value)>,
    #[case] enable_sample_device: bool,
    #[case] expected_result: Result<&[u8; 8]>,
) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let harness = TestHarness::new(test_parameter_type.into()).await?;
    let test_result =
        get_secret(&harness, policy, rvs, enable_sample_device, expected_result).await;

    unsafe { std::env::remove_var("ENABLE_SAMPLE_DEVICE") };
    harness.cleanup().await?;
    test_result
}

async fn get_secret(
    harness: &TestHarness,
    policy: PolicyType,
    rvs: Vec<(&str, Value)>,
    enable_sample_device: bool,
    expected_result: Result<&[u8; 8]>,
) -> Result<()> {
    harness.wait().await;

    // Set Secret
    info!("TEST: setting secret");
    harness
        .set_secret(SECRET_PATH.to_string(), SECRET_BYTES.as_ref().to_vec())
        .await?;

    // Set Policy
    info!("TEST: setting policy");
    harness.set_policy(policy).await?;

    if enable_sample_device {
        // We don't yet ship a default device attestation policy,
        // so if we are running a test with the sample device,
        // add a very basic gpu policy.
        harness
            .set_attestation_policy(DEVICE_AS_POLICY.to_string(), "default_gpu".to_string())
            .await?;

        // setting env vars is unsafe because it can effect other threads and processes
        // we are running the tests in serial here, so it should be fine, but be sure to
        // unset this in the wrapper function to not mess up the next test.
        // The specific value of this env var does not matter.
        unsafe { std::env::set_var("ENABLE_SAMPLE_DEVICE", "YES") };
    }

    // Set Reference Values
    info!("TEST: setting reference values");
    for (key, value) in rvs {
        harness
            .set_reference_value(key.to_string(), value.clone())
            .await?;
    }

    // Get Secret
    info!("TEST: getting secret");
    let secret = harness.get_secret(SECRET_PATH.to_string()).await;

    // Test Result
    info!("TEST: checking result");

    if expected_result.is_err() {
        // If the test passes, we have a problem.
        if secret.is_ok() {
            bail!("Secret retrieved when test is expected to fail.");
        }
        // If the test fails, make sure the error message matches.
        else {
            if secret.unwrap_err().to_string() != expected_result.unwrap_err().to_string() {
                bail!(
                    "Test is expected to fail, and it did fail, but with the wrong error message."
                );
            };
        }
    }
    // If we expect the test to pass
    else {
        // If the test does not pass, we have a problem.
        if secret.is_err() {
            bail!("Failed to get secret when test is expected to pass.");
        }
        // If we get a secret, make sure it's the right one.
        else {
            if secret? != SECRET_BYTES {
                bail!("Secret retrieved, but secret has wrong value");
            }
        }
    }

    Ok(())
}

const CHECK_CONTRAINDICATED_POLICY: &str = "
package policy
import rego.v1

default allow = false

allow if {
    input[\"submods\"][\"cpu0\"][\"ear.status\"] != \"contraindicated\"
}
";

const CHECK_CONTRAINDICATED_DEVICE_POLICY: &str = "
package policy
import rego.v1

default allow = false

allow if {
    input[\"submods\"][\"cpu0\"][\"ear.status\"] != \"contraindicated\"
    input[\"submods\"][\"gpu0\"][\"ear.status\"] != \"contraindicated\"
}
";

const DEVICE_AS_POLICY: &str = "
package policy
import rego.v1

default hardware := 97

hardware := 2 if {
    input.sampledevice.svn in data.reference.device_svn
}
";
