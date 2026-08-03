// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use openssl::pkey::PKey;
use rstest::rstest;
use serial_test::serial;
use tracing::info;

extern crate integration_tests;
use crate::integration_tests::common::{
    init_tracing, KbsConfigType, PolicyType, TestHarness, TestParameters, ADMIN_ROLE,
};

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
#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_policy(#[case] test_config: KbsConfigType, #[case] valid_key: bool) -> Result<()> {
    init_tracing();

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await?;

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
                    .contains("Cannot verify token with any of the issuers") =>
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
            Err(e)
                if e.to_string()
                    .contains("DenyAll authorization_mode is enabled") =>
            {
                return Ok(())
            }
            _ => (),
        }
    }

    if test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin {
        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints are restricted, but admin operation was successful.")
            }
            Err(e)
                if e.to_string()
                    .contains(&format!("Role {ADMIN_ROLE} not allowed")) =>
            {
                return Ok(());
            }
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
#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_attestation_policy(
    #[case] test_config: KbsConfigType,
    #[case] valid_key: bool,
) -> Result<()> {
    init_tracing();

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await?;

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
                    .contains("Cannot verify token with any of the issuers") =>
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
            Err(e)
                if e.to_string()
                    .contains("DenyAll authorization_mode is enabled") =>
            {
                return Ok(())
            }
            _ => (),
        }
    }

    if test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin {
        use integration_tests::common::ADMIN_ROLE;

        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints are restricted, but admin operation was successful.")
            }
            Err(e)
                if e.to_string()
                    .contains(&format!("Role {ADMIN_ROLE} not allowed")) =>
            {
                return Ok(());
            }
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
// The /metrics endpoint can be protected by admin authentication (opt-in via
// http_server.require_admin_auth_metrics): no token is denied, a valid token is
// allowed, and disabled/restricted admin backends deny even authenticated requests.
//
#[rstest]
#[case::metrics_no_token(KbsConfigType::EarTokenBuiltInRvps, false)]
#[case::metrics_with_valid_token(KbsConfigType::EarTokenBuiltInRvps, true)]
#[case::metrics_with_deny_admin_backend(KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin, true)]
#[case::metrics_with_restricted_simple_backend(
    KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin,
    true
)]
#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_requires_admin_auth(
    #[case] test_config: KbsConfigType,
    #[case] provide_token: bool,
) -> Result<()> {
    init_tracing();

    let deny_all = test_config == KbsConfigType::EarTokenBuiltInRvpsDenyAllAdmin;
    let restricted = test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin;

    let mut params = TestParameters::from(test_config);
    params.require_admin_auth_metrics = true;
    let harness = TestHarness::new(params).await?;
    harness.wait().await?;

    let token = provide_token.then(|| harness.sign_admin_token().expect("admin token"));
    let res = harness.get_metrics(token).await?;

    harness.cleanup().await?;

    if deny_all {
        assert_eq!(
            res.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "metrics must be denied when the admin backend is disabled"
        );
        return Ok(());
    }

    if restricted {
        assert_eq!(
            res.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "metrics must be denied for roles not allowed by the restricted ACL"
        );
        return Ok(());
    }

    if provide_token {
        assert_eq!(
            res.status(),
            reqwest::StatusCode::OK,
            "metrics must be reachable with a valid admin token"
        );
        let body = res.text().await?;
        assert!(
            body.contains("kbs_build_info"),
            "expected metrics body to contain kbs_build_info, got: {body}"
        );
    } else {
        assert_eq!(
            res.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "metrics must be denied without an admin token"
        );
    }

    Ok(())
}

//
// With http_server.require_admin_auth_metrics disabled (the default), /metrics is
// served without any authentication, preserving backward compatibility.
//
#[rstest]
#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn metrics_unprotected_by_default() -> Result<()> {
    init_tracing();

    let harness = TestHarness::new(KbsConfigType::EarTokenBuiltInRvps.into()).await?;
    harness.wait().await?;

    let res = harness.get_metrics(None).await?;

    harness.cleanup().await?;

    assert_eq!(
        res.status(),
        reqwest::StatusCode::OK,
        "metrics must be reachable without an admin token when protection is off"
    );
    let body = res.text().await?;
    assert!(
        body.contains("kbs_build_info"),
        "expected metrics body to contain kbs_build_info, got: {body}"
    );

    Ok(())
}

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
#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn set_secret(#[case] test_config: KbsConfigType, #[case] valid_key: bool) -> Result<()> {
    init_tracing();

    let mut harness = TestHarness::new(test_config.clone().into()).await?;
    harness.wait().await?;

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
                    .contains("Cannot verify token with any of the issuers") =>
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
            Err(e)
                if e.to_string()
                    .contains("DenyAll authorization_mode is enabled") =>
            {
                return Ok(())
            }
            _ => (),
        }
    }

    if test_config == KbsConfigType::EarTokenBuiltInRvpsSimpleRestrictedAdmin {
        use integration_tests::common::ADMIN_ROLE;

        match res {
            std::result::Result::Ok(_) => {
                bail!("Admin endpoints are restricted, but admin operation was successful.")
            }
            Err(e)
                if e.to_string()
                    .contains(&format!("Role {ADMIN_ROLE} not allowed")) =>
            {
                return Ok(());
            }
            _ => (),
        }
    }

    res
}
