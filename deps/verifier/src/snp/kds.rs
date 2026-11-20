// SPDX-License-Identifier: Apache-2.0

//! KDS certificate retrieval. Certificate and report verification stay in the SNP verifier.

use anyhow::{Context, Result, bail};
use http_cache_reqwest::{
    Cache, CacheMode, HttpCache, HttpCacheOptions, MokaCacheBuilder, MokaManager,
};
use reqwest::StatusCode;
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use std::{
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime},
};
use tracing::debug;

const MAX_ATTEMPTS: u32 = 4;
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
const CERTIFICATE_TTL: Duration = Duration::from_secs(60 * 60);

static KDS_CLIENT: LazyLock<ClientWithMiddleware> = LazyLock::new(|| build_client(CERTIFICATE_TTL));

fn build_client(ttl: Duration) -> ClientWithMiddleware {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(Duration::from_secs(5))
        // reqwest's built-in retries have no backoff or Retry-After support.
        .retry(reqwest::retry::never())
        .build()
        .expect("build KDS HTTP client");
    ClientBuilder::new(client)
        .with(Cache(HttpCache {
            mode: CacheMode::ForceCache,
            manager: MokaManager::new(MokaCacheBuilder::new(1024).time_to_live(ttl).build()),
            options: HttpCacheOptions {
                cache_status_headers: true,
                max_ttl: Some(ttl),
                // ForceCache must not retain rate limits or other HTTP errors.
                response_cache_mode_fn: Some(Arc::new(|_, response| {
                    (response.status != 200).then_some(CacheMode::NoStore)
                })),
                ..Default::default()
            },
        }))
        .build()
}

pub(super) async fn fetch(url: &str) -> Result<Vec<u8>> {
    tokio::time::timeout(FETCH_TIMEOUT, download_vcek(&KDS_CLIENT, url))
        .await
        .with_context(|| format!("VCEK download timed out: {url}"))?
}

async fn download_vcek(client: &ClientWithMiddleware, url: &str) -> Result<Vec<u8>> {
    for attempt in 0..MAX_ATTEMPTS {
        let response = client.get(url).send().await;
        let retry_after = match response {
            Ok(response) => {
                let status = response.status();
                debug!(?status, url, attempt, "VCEK fetch");
                if status == StatusCode::OK {
                    return Ok(response
                        .bytes()
                        .await
                        .context("Unable to read VCEK")?
                        .to_vec());
                } else {
                    if status != StatusCode::TOO_MANY_REQUESTS || attempt + 1 == MAX_ATTEMPTS {
                        bail!("Unable to fetch VCEK from URL: {status}, {url}");
                    }
                    response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| parse_retry_after(value, SystemTime::now()))
                }
            }
            // The cache middleware erases underlying transport error types.
            // Retry send failures within the same bounded attempt/deadline limits.
            Err(_) if attempt + 1 < MAX_ATTEMPTS => None,
            Err(error) => return Err(error).context("Unable to send request for VCEK"),
        };
        let backoff = INITIAL_BACKOFF * (1 << attempt);
        let jitter = Duration::from_millis(rand::random_range(0..=250));
        // Retry-After is a minimum, never truncate it. The outer fetch deadline
        // cancels waits that exceed the total budget without sending early.
        let delay = retry_after
            .unwrap_or_default()
            .max(backoff)
            .saturating_add(jitter);
        if delay > FETCH_TIMEOUT {
            bail!("KDS retry delay exceeds fetch deadline: {url}");
        }
        debug!(url, ?delay, "Waiting before retrying KDS request");
        tokio::time::sleep(delay).await;
    }
    unreachable!("every final attempt returns a result")
}

fn parse_retry_after(value: &str, now: SystemTime) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<u64>() {
        return Some(Duration::from_secs(seconds));
    }
    httpdate::parse_http_date(value)
        .ok()
        .map(|date| date.duration_since(now).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::method};

    fn certificate() -> Vec<u8> {
        include_bytes!("../../test_data/snp/test-vcek.der").to_vec()
    }

    #[tokio::test]
    async fn sequential_layers_reuse_certificates_without_freshness_headers() {
        for headers in [None, Some("no-cache"), Some("no-store")] {
            let server = MockServer::start().await;
            let mut response = ResponseTemplate::new(200).set_body_bytes(certificate());
            if let Some(value) = headers {
                response = response.insert_header("Cache-Control", value);
            }
            Mock::given(method("GET"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
            let client = build_client(CERTIFICATE_TTL);
            for _ in 0..7 {
                assert_eq!(
                    download_vcek(&client, &server.uri()).await.unwrap(),
                    certificate()
                );
            }
        }
    }

    #[tokio::test]
    async fn rate_limits_honor_retry_after_and_are_not_cached() {
        let server = MockServer::start().await;
        let count = AtomicUsize::new(0);
        Mock::given(method("GET"))
            .respond_with(move |_: &wiremock::Request| {
                if count.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(429).insert_header("Retry-After", "2")
                } else {
                    ResponseTemplate::new(200).set_body_bytes(certificate())
                }
            })
            .expect(2)
            .mount(&server)
            .await;
        let client = build_client(CERTIFICATE_TTL);
        let started = tokio::time::Instant::now();
        assert_eq!(
            download_vcek(&client, &server.uri()).await.unwrap(),
            certificate()
        );
        assert!(started.elapsed() >= Duration::from_secs(2));
        assert_eq!(
            download_vcek(&client, &server.uri()).await.unwrap(),
            certificate()
        );
    }

    #[tokio::test]
    async fn custom_hosts_receive_bounded_attempts_with_backoff() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .expect(MAX_ATTEMPTS as u64)
            .mount(&server)
            .await;
        let started = tokio::time::Instant::now();
        let url = server.uri().replace("127.0.0.1", "localhost");
        assert!(
            download_vcek(&build_client(CERTIFICATE_TTL), &url)
                .await
                .is_err()
        );
        assert!(started.elapsed() >= Duration::from_secs(7));
    }

    #[tokio::test]
    async fn permanent_errors_are_not_retried_or_cached() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(404))
            .expect(2)
            .mount(&server)
            .await;
        let client = build_client(CERTIFICATE_TTL);
        for _ in 0..2 {
            assert!(download_vcek(&client, &server.uri()).await.is_err());
        }
    }

    #[tokio::test]
    async fn expired_certificates_are_downloaded_again() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(certificate()))
            .expect(2)
            .mount(&server)
            .await;
        let client = build_client(Duration::from_millis(20));
        download_vcek(&client, &server.uri()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        download_vcek(&client, &server.uri()).await.unwrap();
    }

    #[tokio::test]
    async fn refused_connections_are_retried_with_backoff() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let started = tokio::time::Instant::now();
        let error = download_vcek(&build_client(CERTIFICATE_TTL), &url)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("Unable to send request"));
        assert!(started.elapsed() >= Duration::from_secs(7));
    }

    #[tokio::test]
    async fn excessive_retry_after_does_not_retry_early() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(429).insert_header("Retry-After", "18446744073709551615"),
            )
            .expect(1)
            .mount(&server)
            .await;
        assert!(
            download_vcek(&build_client(CERTIFICATE_TTL), &server.uri())
                .await
                .is_err()
        );
    }

    #[test]
    fn retry_after_supports_seconds_and_dates() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        assert_eq!(parse_retry_after("12", now), Some(Duration::from_secs(12)));
        let future = httpdate::fmt_http_date(now + Duration::from_secs(20));
        assert_eq!(
            parse_retry_after(&future, now),
            Some(Duration::from_secs(20))
        );
        let past = httpdate::fmt_http_date(now - Duration::from_secs(20));
        assert_eq!(parse_retry_after(&past, now), Some(Duration::ZERO));
        assert_eq!(parse_retry_after("invalid", now), None);
    }
}
