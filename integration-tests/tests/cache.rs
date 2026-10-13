// Copyright (c) 2026 by The Confidential Container Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! End-to-end tests of the KBS cache admin API.

use anyhow::{ensure, Result};
use serial_test::serial;

extern crate integration_tests;
use crate::integration_tests::common::{init_tracing, KbsConfigType, TestHarness};

const NAMESPACE: &str = "snp_vcek";
const KEY: &str = "Milan/0a1b2c/bl03_tee00_snp08_ucode115";

#[serial(integration_ports)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cache_admin_api() -> Result<()> {
    init_tracing();
    let harness = TestHarness::new(KbsConfigType::EarTokenBuiltInRvps.into()).await?;
    harness.wait().await?;
    let result = exercise(&harness).await;
    harness.cleanup().await?;
    result
}

async fn exercise(harness: &TestHarness) -> Result<()> {
    let url = harness.kbs_url();
    let token = || harness.admin_token().map(Some);

    // The KBS registers its JWK set namespace at startup.
    let stats = kbs_client::get_cache_stats(url, token()?, None, vec![]).await?;
    ensure!(stats.get("kbs_jwks").is_some(), "kbs_jwks missing: {stats}");

    kbs_client::set_cache_entry(url, token()?, NAMESPACE, KEY, b"vcek".to_vec(), vec![]).await?;
    let value = kbs_client::get_cache_entry(url, token()?, NAMESPACE, KEY, vec![]).await?;
    ensure!(
        value.as_deref() == Some(&b"vcek"[..]),
        "unexpected value {value:?}"
    );

    let stats = kbs_client::get_cache_stats(url, token()?, Some(NAMESPACE), vec![]).await?;
    ensure!(
        stats["keys"] == serde_json::json!([KEY]),
        "unexpected keys: {stats}"
    );
    ensure!(stats["stats"]["entries"] == 1, "unexpected stats: {stats}");

    kbs_client::delete_cache_entry(url, token()?, NAMESPACE, Some(KEY), vec![]).await?;
    let value = kbs_client::get_cache_entry(url, token()?, NAMESPACE, KEY, vec![]).await?;
    ensure!(value.is_none(), "entry still present after delete");
    ensure!(
        kbs_client::delete_cache_entry(url, token()?, NAMESPACE, Some(KEY), vec![])
            .await
            .is_err(),
        "deleting a missing entry should fail"
    );

    // Seeding from a directory tree, as for an air-gapped deployment.
    let dir = tempfile::tempdir()?;
    std::fs::create_dir_all(dir.path().join(NAMESPACE).join("Genoa/ff"))?;
    std::fs::write(dir.path().join(NAMESPACE).join("Genoa/ff/tcb"), b"x")?;
    let uploaded = kbs_client::upload_cache_directory(url, token()?, dir.path(), vec![]).await?;
    ensure!(uploaded == 1, "uploaded {uploaded} entries");
    ensure!(
        kbs_client::get_cache_entry(url, token()?, NAMESPACE, "Genoa/ff/tcb", vec![])
            .await?
            .is_some(),
        "uploaded entry missing"
    );

    kbs_client::delete_cache_entry(url, token()?, NAMESPACE, None, vec![]).await?;
    let stats = kbs_client::get_cache_stats(url, token()?, Some(NAMESPACE), vec![]).await?;
    ensure!(
        stats["stats"]["entries"] == 0,
        "namespace not cleared: {stats}"
    );
    kbs_client::purge_cache(url, token()?, vec![]).await?;

    // Keys and namespaces are validated by the client...
    ensure!(
        kbs_client::set_cache_entry(url, token()?, NAMESPACE, "bad key", vec![], vec![])
            .await
            .is_err(),
        "invalid key accepted"
    );
    ensure!(
        kbs_client::get_cache_stats(url, token()?, Some("Bad-Namespace"), vec![])
            .await
            .is_err(),
        "invalid namespace accepted"
    );

    // ...and by the server.
    let http = reqwest::Client::new();
    for path in ["snp_vcek/bad%20key", "Bad-Namespace", "snp_vcek/a%2F..%2Fb"] {
        let status = http
            .put(format!("{url}/kbs/v0/cache/{path}"))
            .bearer_auth(harness.admin_token()?)
            .body("x")
            .send()
            .await?
            .status();
        ensure!(!status.is_success(), "server accepted cache/{path}");
    }

    // Trust anchors cannot be written through the API.
    let status = http
        .put(format!("{url}/kbs/v0/cache/kbs_jwks/k"))
        .bearer_auth(harness.admin_token()?)
        .body("{}")
        .send()
        .await?
        .status();
    ensure!(
        status == reqwest::StatusCode::FORBIDDEN,
        "trust anchor write returned {status}"
    );

    // Statistics are exported as Prometheus metrics.
    let metrics = http
        .get(format!("{url}/metrics"))
        .send()
        .await?
        .text()
        .await?;
    ensure!(
        metrics.contains("kbs_cache_entries{namespace=\"snp_vcek\"}"),
        "cache metrics missing"
    );

    // Admin authentication is required.
    ensure!(
        kbs_client::get_cache_stats(url, None, None, vec![])
            .await
            .is_err(),
        "anonymous cache access allowed"
    );
    Ok(())
}
