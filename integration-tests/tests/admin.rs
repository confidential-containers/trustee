// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use log::info;
use openssl::pkey::PKey;
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
#[case::set_policy_with_restricted_simple_backend(
    KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin,
    true
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn set_policy(#[case] test_config: KbsConfigType, #[case] valid_key: bool) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await;

    if !valid_key {
        info!("TEST: replacing admin private key");

        let auth_keypair = PKey::generate_ed25519()?;
        let auth_privkey = String::from_utf8(auth_keypair.private_key_to_pem_pkcs8()?)?;

        harness.auth_privkey = auth_privkey;
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

    if test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin {
         match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints are restricted, but admin operation was successful.")
            }
            Err(e) if e.to_string().contains("Admin Token could not be verified for any admin persona") => return Ok(()),
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
#[case::set_attestation_policy_with_restricted_simple_backend(
    KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin,
    true
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

        let auth_keypair = PKey::generate_ed25519()?;
        let auth_privkey = String::from_utf8(auth_keypair.private_key_to_pem_pkcs8()?)?;

        harness.auth_privkey = auth_privkey;
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

    if test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin {
         match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints are restricted, but admin operation was successful.")
            }
            Err(e) if e.to_string().contains("Admin Token could not be verified for any admin persona") => return Ok(()),
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
#[case::set_secret_with_restricted_simple_backend(
    KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin,
    true
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn set_secret(#[case] test_config: KbsConfigType, #[case] valid_key: bool) -> Result<()> {
    let _ = env_logger::try_init_from_env(env_logger::Env::new().default_filter_or("debug"));

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await;

    if !valid_key {
        info!("TEST: replacing admin private key");

        let auth_keypair = PKey::generate_ed25519()?;
        let auth_privkey = String::from_utf8(auth_keypair.private_key_to_pem_pkcs8()?)?;

        harness.auth_privkey = auth_privkey;
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

    if test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin {
         match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints are restricted, but admin operation was successful.")
            }
            Err(e) if e.to_string().contains("Admin Token could not be verified for any admin persona") => return Ok(()),
            _ => (),
        }
    }


    res
}
