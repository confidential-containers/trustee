// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use anyhow::{Context, Result, ensure};
use async_trait::async_trait;
use kbs::{ApiServer, KbsConfig};
use pingora::server::{RunArgs, ShutdownSignal, ShutdownSignalWatch};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

const SAMPLE_AS_POLICY: &str =
    include_str!("../../../attestation-service/tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego");

struct ProxyShutdown(watch::Receiver<()>);

#[async_trait]
impl ShutdownSignalWatch for ProxyShutdown {
    async fn recv(&self) -> ShutdownSignal {
        let _ = self.0.clone().changed().await;
        ShutdownSignal::FastShutdown
    }
}

async fn echo(request: HttpRequest, hits: web::Data<AtomicUsize>) -> web::Json<Value> {
    hits.fetch_add(1, Ordering::SeqCst);
    let has_authorization = request.headers().contains_key("authorization");
    println!(
        "Echo received {} {} (Authorization header present: {has_authorization})",
        request.method(),
        request.uri()
    );
    web::Json(json!({
        "uri": request.uri().to_string(),
        "has_authorization": has_authorization,
    }))
}

async fn wait_until_healthy(client: &Client, service: &str, addr: SocketAddr) -> Result<()> {
    let url = format!("http://{addr}/healthz");
    timeout(Duration::from_secs(20), async {
        loop {
            if let Ok(response) = client.get(&url).send().await
                && response.status() == StatusCode::OK
            {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .with_context(|| format!("waiting for {service} at {url}"))?;
    println!("{service} ready at http://{addr}");
    Ok(())
}

async fn exercise_proxy(
    kbs: SocketAddr,
    proxy: SocketAddr,
    upstream: SocketAddr,
    hits: &AtomicUsize,
) -> Result<()> {
    let client = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()?;
    tokio::try_join!(
        wait_until_healthy(&client, "KBS", kbs),
        wait_until_healthy(&client, "Proxy", proxy),
        wait_until_healthy(&client, "Echo server", upstream)
    )?;

    println!("Starting sample attestation with KBS");
    let token = timeout(
        Duration::from_secs(30),
        kbs_client::attestation(&format!("http://{kbs}"), None, vec![], None),
    )
    .await
    .context("timed out obtaining sample attestation")??;
    println!("kbs-client received the signed attestation token");

    let path = "/echo?message=hello";
    let url = format!("http://{proxy}{path}");
    for (credential, request) in [
        ("without a token", client.get(&url)),
        (
            "with an invalid token",
            client.get(&url).bearer_auth("invalid"),
        ),
    ] {
        let response = request.send().await?;
        println!("GET {path} {credential} → {}", response.status());
        ensure!(
            response.status() == StatusCode::UNAUTHORIZED,
            "expected 401, got {}",
            response.status()
        );
    }

    println!("Sending GET {path} through the proxy with the sample token");
    let response = client.get(&url).bearer_auth(token).send().await?;
    println!("Proxy returned {}", response.status());
    ensure!(
        response.status() == StatusCode::OK,
        "expected 200, got {}",
        response.status()
    );
    ensure!(
        response.json::<Value>().await? == json!({"uri": path, "has_authorization": false}),
        "unexpected echo response"
    );
    ensure!(
        hits.load(Ordering::SeqCst) == 1,
        "only the authorized request should reach the echo server"
    );
    println!("Verified that exactly one request reached /echo");
    Ok(())
}

#[test]
fn e2e_test() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let policy_dir = dir.path().join("attestation_service_policy");
    fs::create_dir(&policy_dir)?;
    fs::write(policy_dir.join("default_cpu.rego"), SAMPLE_AS_POLICY)?;

    let echo_listener = TcpListener::bind("127.0.0.1:0")?;
    let kbs_listener = TcpListener::bind("127.0.0.1:0")?;
    let proxy_listener = TcpListener::bind("127.0.0.1:0")?;
    let kbs_addr = kbs_listener.local_addr()?;
    let proxy_addr = proxy_listener.local_addr()?;
    let echo_addr = echo_listener.local_addr()?;

    let mut config = KbsConfig::try_from(Path::new("tests/kbs-config.toml"))?;
    config.http_server.sockets = vec![kbs_addr];
    config.storage_backend.backends.local_fs = Some(key_value_storage::local_fs::Config {
        dir_path: dir
            .path()
            .to_str()
            .context("invalid temporary directory path")?
            .to_owned(),
    });

    let proxy_config = dir.path().join("proxy.toml");
    fs::write(
        &proxy_config,
        format!(
            "listen_address = \"{proxy_addr}\"\nupstream_url = \"http://{echo_addr}\"\n{}",
            include_str!("proxy-config.toml")
        ),
    )?;

    let hits = Arc::new(AtomicUsize::new(0));
    let echo_hits = web::Data::from(Arc::clone(&hits));
    println!("Starting KBS, the attestation proxy, and the echo server");
    thread::scope(|scope| -> Result<()> {
        // Dropping the sender on success, error, or panic stops both server threads.
        let (stop, mut stopped) = watch::channel(());
        let proxy_shutdown = ProxyShutdown(stopped.clone());
        let kbs_thread = scope.spawn(move || -> Result<()> {
            actix_web::rt::System::new().block_on(async move {
                let kbs = ApiServer::new(config).await?;
                drop(kbs_listener);
                let kbs = kbs.server()?;
                let upstream = HttpServer::new(move || {
                    App::new()
                        .app_data(echo_hits.clone())
                        .route("/healthz", web::get().to(HttpResponse::Ok))
                        .route("/echo", web::get().to(echo))
                })
                .workers(1)
                .disable_signals()
                .listen(echo_listener)?
                .run();

                let kbs_handle = kbs.handle();
                let upstream_handle = upstream.handle();
                actix_web::rt::spawn(async move {
                    let _ = stopped.changed().await;
                    tokio::join!(kbs_handle.stop(false), upstream_handle.stop(false));
                });
                tokio::try_join!(kbs, upstream)?;
                Ok(())
            })
        });
        let proxy_thread = scope.spawn(move || -> Result<()> {
            let server = attestation_proxy::build_server(&proxy_config)?;
            drop(proxy_listener);
            server.run(RunArgs {
                shutdown_signal: Box::new(proxy_shutdown),
            });
            Ok(())
        });

        let result = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(exercise_proxy(kbs_addr, proxy_addr, echo_addr, &hits));
        drop(stop);
        kbs_thread.join().expect("KBS thread panicked")?;
        proxy_thread.join().expect("proxy thread panicked")?;
        println!("KBS, proxy, and echo server stopped");
        result
    })
}
