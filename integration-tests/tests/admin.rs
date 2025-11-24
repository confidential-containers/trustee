// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use log::info;
use rstest::rstest;
use serial_test::serial;

extern crate integration_tests;
use crate::integration_tests::common::{KbsConfigType, PolicyType, TestHarness};

//
// Set the kbs policy with the a valid admin private key
// and with the wrong admin private key.
//
#[rstest]
#[case::set_policy_with_valid_key(KbsConfigType::EarTokenBuiltInRvps, true)]
#[case::set_policy_with_invalid_key(KbsConfigType::EarTokenBuiltInRvps, false)]
#[case::set_policy_with_deny_admin_backend(KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin, false)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn set_policy(#[case] test_config: KbsConfigType, #[case] valid_key: bool) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await;

    if !valid_key {
        info!("TEST: replacing admin private key");
        harness.replace_admin_token()?;
    }

    info!("TEST: setting policy");
    let res = harness.set_policy(PolicyType::AllowAll).await;

    harness.cleanup().await?;
    if !valid_key {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin key is invalid, but admin operation was successful")
            }
            Err(e)
                if e.to_string()
                    .contains("Admin Token could not be verified for any admin persona") =>
            {
                return Ok(())
            }
            _ => (),
        }
    }

    if test_config == KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints disabled, but admin operation was successful")
            }
            Err(e) if e.to_string().contains("Admin endpoints disabled") => return Ok(()),
            _ => (),
        }
    }

    res
}

//
// Set the attestation policy with the a valid admin private key
// and with the wrong admin private key.
//
#[rstest]
#[case::set_attestation_policy_with_valid_key(KbsConfigType::EarTokenBuiltInRvps, true)]
#[case::set_attestation_policy_with_invalid_key(KbsConfigType::EarTokenBuiltInRvps, false)]
#[case::set_attestation_policy_with_deny_admin_backend(
    KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin,
    false
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn set_attestation_policy(
    #[case] test_config: KbsConfigType,
    #[case] valid_key: bool,
) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await;

    if !valid_key {
        info!("TEST: replacing admin private key");
        harness.replace_admin_token()?;
    }

    info!("TEST: setting attestation policy");
    let res = harness
        .set_attestation_policy(DUMMY_POLICY.to_string(), "fake_policy_id".to_string())
        .await;

    harness.cleanup().await?;
    if !valid_key {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin key is invalid, but admin operation was successful")
            }
            Err(e)
                if e.to_string()
                    .contains("Admin Token could not be verified for any admin persona") =>
            {
                return Ok(())
            }
            _ => (),
        }
    }

    if test_config == KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints disabled, but admin operation was successful")
            }
            Err(e) if e.to_string().contains("Admin endpoints disabled") => return Ok(()),
            _ => (),
        }
    }

    res
}

const DUMMY_POLICY: &str = "
package policy
import rego.v1

default executables = 97
";

//
// Set a secret with the a valid admin private key
// and with the wrong admin private key.
//
#[rstest]
#[case::set_secret_with_valid_key(KbsConfigType::EarTokenBuiltInRvps, true)]
#[case::set_secret_with_invalid_key(KbsConfigType::EarTokenBuiltInRvps, false)]
#[case::set_secret_with_deny_admin_backend(KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin, false)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn set_secret(#[case] test_config: KbsConfigType, #[case] valid_key: bool) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await;

    if !valid_key {
        info!("TEST: replacing admin private key");
        harness.replace_admin_token()?;
    }

    info!("TEST: setting secret");
    let res = harness.set_secret("a/b/c".to_string(), vec![0u8; 10]).await;

    harness.cleanup().await?;
    if !valid_key {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin key is invalid, but admin operation was successful")
            }
            Err(e)
                if e.to_string()
                    .contains("Admin Token could not be verified for any admin persona") =>
            {
                return Ok(())
            }
            _ => (),
        }
    }

    if test_config == KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints disabled, but admin operation was successful")
            }
            Err(e) if e.to_string().contains("Admin endpoints disabled") => return Ok(()),
            _ => (),
        }
    }

    res
}

// To avoid making the cases matrix for the other tests too complex,
// make a separate test for the password admin interface.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn password_admin_test() -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let mut harness =
        TestHarness::new(KbsConfigType::EarTokenBuiltInRvpsPasswordAdmin.into()).await?;
    harness.wait().await;

    info!("TEST: logging in with invalid credentials");
    harness
        .login("test1".to_string(), "banana".to_string())
        .await
        .context("Able to log in with wrong credentials.")?;

    harness
        .login("test1".to_string(), "password2".to_string())
        .await
        .context("Able to log in with wrong credentials.")?;

    harness
        .login("test2".to_string(), "password1".to_string())
        .await
        .context("Able to log in with wrong credentials.")?;

    info!("TEST: login with valid credentials");
    harness
        .login("test2".to_string(), "password2".to_string())
        .await?;

    info!("TEST: setting secret");
    harness
        .set_secret("a/b/c".to_string(), vec![0u8; 10])
        .await?;

    info!("TEST: tampering with admin token");
    harness
        .admin_token
        .as_mut()
        .context("Could not get admin token.")?
        .replace_range(3..5, "x");

    info!("TEST: setting secret");
    harness
        .set_secret("a/b/c".to_string(), vec![0u8; 10])
        .await
        .context("Able to log in with wrong credentials.")?;

    harness.cleanup().await?;

    Ok(())
}
