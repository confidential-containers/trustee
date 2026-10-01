use super::{get_oid_octets, verify_report_tcb, verify_vcek_chain, ProcessorGeneration, HW_ID_OID};
use anyhow::{bail, Context, Result};
use moka::future::Cache;
use openssl::x509::X509;
use reqwest::{header::RETRY_AFTER, StatusCode};
use sev::{certs::snp::Certificate, firmware::guest::AttestationReport};
use std::{
    sync::{Arc, LazyLock},
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
struct SharedDownloadError(Arc<anyhow::Error>);

impl std::fmt::Display for SharedDownloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl std::error::Error for SharedDownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref().as_ref())
    }
}

const MAX_ATTEMPTS: u32 = 4;
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

const CERTIFICATE_TTL: Duration = Duration::from_secs(60 * 60);

static CLIENT: LazyLock<reqwest::Client> = LazyLock::new(reqwest::Client::new);
static CERTIFICATES: LazyLock<Cache<String, Vec<u8>>> = LazyLock::new(|| {
    Cache::builder()
        .max_capacity(1024)
        .time_to_live(CERTIFICATE_TTL)
        .build()
});

pub(super) async fn fetch(
    url: &str,
    report: &AttestationReport,
    proc_gen: &ProcessorGeneration,
) -> Result<Vec<u8>> {
    fetch_cached(&CERTIFICATES, url, report, proc_gen).await
}

async fn fetch_cached(
    cache: &Cache<String, Vec<u8>>,
    url: &str,
    report: &AttestationReport,
    proc_gen: &ProcessorGeneration,
) -> Result<Vec<u8>> {
    cache
        .try_get_with(url.to_owned(), async {
            debug!(url, "VCEK certificate cache miss; fetching from KDS");
            let bytes = tokio::time::timeout(FETCH_TIMEOUT, download_vcek(url))
                .await
                .with_context(|| format!("VCEK download timed out: {url}"))??;
            validate_vcek(&bytes, report, proc_gen)?;
            Ok::<_, anyhow::Error>(bytes)
        })
        .await
        .map_err(|error| anyhow::Error::new(SharedDownloadError(error)))
}

fn validate_vcek(
    bytes: &[u8],
    report: &AttestationReport,
    proc_gen: &ProcessorGeneration,
) -> Result<()> {
    let vcek = Certificate::from(X509::from_der(bytes).context("Invalid KDS VCEK certificate")?);
    verify_vcek_chain(&vcek, proc_gen)?;

    let parsed = X509Certificate::from_der(bytes)?.1.tbs_certificate;
    if get_oid_octets::<64>(&parsed, HW_ID_OID)? != report.chip_id {
        bail!("KDS VCEK chip ID mismatch");
    }

    verify_report_tcb(report, vcek, proc_gen.clone())
        .context("KDS VCEK does not match the reported TCB")
}

fn retry_delay(value: Option<&str>, attempt: u32, now: SystemTime) -> Result<Duration> {
    let server_delay = value.and_then(|value| {
        value
            .parse::<u64>()
            .ok()
            .map(Duration::from_secs)
            .or_else(|| {
                httpdate::parse_http_date(value)
                    .ok()
                    .map(|date| date.duration_since(now).unwrap_or_default())
            })
    });

    if server_delay.is_some_and(|delay| delay > MAX_RETRY_DELAY) {
        bail!("KDS Retry-After exceeds the 30-second retry delay limit");
    }

    let backoff = Duration::from_secs(1 << attempt);
    let delay = server_delay.unwrap_or_default().max(backoff);
    let jitter = Duration::from_millis(u64::from(rand::random::<u8>()));

    Ok((delay + jitter).min(MAX_RETRY_DELAY))
}

async fn download_vcek(url: &str) -> Result<Vec<u8>> {
    for attempt in 0..MAX_ATTEMPTS {
        let response = CLIENT
            .get(url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .context("Unable to send request for VCEK")?;
        let status = response.status();
        debug!(?status, url, "VCEK fetch");
        if status == StatusCode::OK {
            return Ok(response
                .bytes()
                .await
                .context("Unable to read VCEK")?
                .to_vec());
        }
        if status != StatusCode::TOO_MANY_REQUESTS || attempt + 1 == MAX_ATTEMPTS {
            bail!("Unable to fetch VCEK from URL: {status}, {url}");
        }
        let delay = retry_delay(
            response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok()),
            attempt,
            SystemTime::now(),
        )
        .with_context(|| format!("Unable to fetch VCEK from URL: {status}, {url}"))?;
        drop(response);
        warn!(
            ?delay,
            attempt = attempt + 1,
            "KDS rate limited VCEK download; retrying"
        );
        tokio::time::sleep(delay).await;
    }
    unreachable!("MAX_ATTEMPTS is nonzero")
}

#[cfg(test)]
mod tests {
    use super::*;
    use sev::certs::snp::Verifiable;
    use sev::parser::ByteParser;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        task::{JoinHandle, JoinSet},
    };

    const VCEK: &[u8] = include_bytes!("../../test_data/snp/test-vcek.der");
    const REPORT: &[u8] = include_bytes!("../../test_data/snp/test-report.bin");

    async fn fetch(url: &str) -> Result<Vec<u8>> {
        super::fetch(
            url,
            &AttestationReport::from_bytes(REPORT).unwrap(),
            &ProcessorGeneration::Milan,
        )
        .await
    }

    struct Server {
        url: String,
        requests: Arc<AtomicUsize>,
        task: JoinHandle<()>,
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    impl Server {
        async fn new(responses: Vec<(u16, &'static str)>) -> Self {
            Self::with_bodies(
                responses
                    .into_iter()
                    .map(|(status, headers)| (status, headers, VCEK.to_vec()))
                    .collect(),
            )
            .await
        }

        async fn with_bodies(responses: Vec<(u16, &'static str, Vec<u8>)>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/vcek?ucodeSPL=21", listener.local_addr().unwrap());
            let requests = Arc::new(AtomicUsize::new(0));
            let count = requests.clone();
            let task = tokio::spawn(async move {
                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    let mut buffer = [0; 1024];
                    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                        let n = stream.read(&mut buffer).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..n]);
                    }
                    let index = count.fetch_add(1, Ordering::SeqCst);
                    let (status, headers, body) = &responses[index.min(responses.len() - 1)];
                    // Give concurrent callers time to join the same download.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let response = format!(
                        "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n", body.len()
                    );
                    // A cancellation test can close the connection early.
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.write_all(body).await;
                }
            });
            Self {
                url,
                requests,
                task,
            }
        }

        fn count(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    async fn concurrent_fetches(url: &str, success: bool) {
        let mut tasks = JoinSet::new();
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        for _ in 0..16 {
            let url = url.to_owned();
            let barrier = barrier.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                fetch(&url).await
            });
        }
        while let Some(result) = tasks.join_next().await {
            let result = result.unwrap();
            if success {
                assert_eq!(result.unwrap(), VCEK);
            } else {
                assert!(result.unwrap_err().to_string().contains("429"));
            }
        }
    }

    #[tokio::test]
    async fn concurrent_downloads_share_retries_and_certificate_cache() {
        let server = Server::new(vec![
            (429, "Retry-After: 1\r\nCache-Control: no-store\r\n"),
            (200, "Cache-Control: no-store\r\n"),
        ])
        .await;
        concurrent_fetches(&server.url, true).await;
        assert_eq!(server.count(), 2);
        assert_eq!(fetch(&server.url).await.unwrap(), VCEK);
        assert_eq!(
            server.count(),
            2,
            "later calls should use the certificate cache"
        );
        fetch(&format!("{}&blSPL=02", server.url)).await.unwrap();
        assert_eq!(
            server.count(),
            3,
            "different TCB URLs must not share certificates"
        );
    }

    #[tokio::test]
    async fn concurrent_failures_share_a_bounded_retry_budget() {
        let server = Server::new(vec![(429, "Cache-Control: no-store\r\n")]).await;
        concurrent_fetches(&server.url, false).await;
        assert_eq!(server.count(), MAX_ATTEMPTS as usize);
    }

    #[tokio::test]
    async fn permanent_errors_are_not_retried_or_retained() {
        let server = Server::new(vec![
            (404, "Cache-Control: no-store\r\n"),
            (200, "Cache-Control: no-store\r\n"),
        ])
        .await;
        assert!(fetch(&server.url)
            .await
            .unwrap_err()
            .to_string()
            .contains("404"));
        assert_eq!(server.count(), 1);
        assert_eq!(fetch(&server.url).await.unwrap(), VCEK);
        assert_eq!(server.count(), 2);
        fetch(&server.url).await.unwrap();
        assert_eq!(
            server.count(),
            2,
            "validated certificates should be retained"
        );
    }

    #[tokio::test]
    async fn excessive_retry_after_does_not_retry_early() {
        let server = Server::new(vec![(429, "Retry-After: 120\r\n")]).await;
        assert!(format!("{:#}", fetch(&server.url).await.unwrap_err()).contains("Retry-After"));
        assert_eq!(server.count(), 1);
    }

    #[tokio::test]
    async fn cancelled_download_can_be_restarted() {
        let server = Server::new(vec![(200, "Cache-Control: no-store\r\n")]).await;
        let url = server.url.clone();
        let first = tokio::spawn(async move { fetch(&url).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Keep a waiter attached when the cache initializer exits.
        let second = fetch(&server.url);
        tokio::pin!(second);
        tokio::select! {
            _ = &mut second => panic!("download should still be pending"),
            _ = tokio::time::sleep(Duration::from_millis(1)) => {}
        }
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), second)
                .await
                .unwrap()
                .unwrap(),
            VCEK
        );
        assert_eq!(server.count(), 2);
    }

    #[test]
    fn retry_after_supports_seconds_dates_and_invalid_values() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let date = httpdate::fmt_http_date(now + Duration::from_secs(10));
        for value in ["10", date.as_str()] {
            let delay = retry_delay(Some(value), 0, now).unwrap();
            assert!(delay >= Duration::from_secs(10));
            assert!(delay < Duration::from_secs(11));
        }
        let past = httpdate::fmt_http_date(now - Duration::from_secs(10));
        for value in [None, Some("invalid"), Some("0"), Some(past.as_str())] {
            let delay = retry_delay(value, 2, now).unwrap();
            assert!(delay >= Duration::from_secs(4));
            assert!(delay < Duration::from_secs(5));
        }
        assert!(retry_delay(Some("31"), 0, now).is_err());
    }

    #[tokio::test]
    async fn seven_sequential_layers_only_download_once_without_http_freshness() {
        for headers in [
            "",
            "Cache-Control: no-cache\r\n",
            "Cache-Control: no-store\r\n",
        ] {
            let server = Server::new(vec![(200, headers)]).await;
            for _ in 0..7 {
                assert_eq!(fetch(&server.url).await.unwrap(), VCEK);
            }
            assert_eq!(server.count(), 1);
        }
    }

    #[tokio::test]
    async fn invalid_certificates_do_not_poison_the_cache() {
        let mut corrupted = VCEK.to_vec();
        // Preserve DER encoding while invalidating the certificate signature.
        *corrupted.last_mut().unwrap() ^= 1;
        for invalid in [b"not a certificate".to_vec(), corrupted] {
            let server = Server::with_bodies(vec![
                (200, "Cache-Control: public, max-age=3600\r\n", invalid),
                (200, "", VCEK.to_vec()),
            ])
            .await;
            assert!(fetch(&server.url).await.is_err());
            assert_eq!(fetch(&server.url).await.unwrap(), VCEK);
            assert_eq!(server.count(), 2);
        }
    }

    #[tokio::test]
    async fn mismatched_chip_or_tcb_is_not_cached() {
        let original = AttestationReport::from_bytes(REPORT).unwrap();
        let mut wrong_chip = original;
        wrong_chip.chip_id[0] ^= 1;
        let mut wrong_tcb = original;
        wrong_tcb.reported_tcb.microcode ^= 1;
        for report in [wrong_chip, wrong_tcb] {
            let server = Server::new(vec![(200, "")]).await;
            assert!(
                super::fetch(&server.url, &report, &ProcessorGeneration::Milan)
                    .await
                    .is_err()
            );
            assert_eq!(fetch(&server.url).await.unwrap(), VCEK);
            assert_eq!(server.count(), 2);
        }
    }

    #[tokio::test]
    async fn invalid_report_does_not_fail_a_shared_certificate_download() {
        let server = Server::new(vec![(200, "")]).await;
        let url = server.url.clone();
        let mut invalid = AttestationReport::from_bytes(REPORT).unwrap();
        invalid.report_data[0] ^= 1;
        let first = tokio::spawn(async move {
            // Start with an invalid report to make it the cache initializer.
            let bytes = super::fetch(&url, &invalid, &ProcessorGeneration::Milan)
                .await
                .unwrap();
            let cert = Certificate::from(X509::from_der(&bytes).unwrap());
            assert!((&cert, &invalid).verify().is_err());
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            while server.count() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let bytes = fetch(&server.url).await.unwrap();
        let cert = Certificate::from(X509::from_der(&bytes).unwrap());
        let valid = AttestationReport::from_bytes(REPORT).unwrap();
        (&cert, &valid).verify().unwrap();
        first.await.unwrap();
        assert_eq!(server.count(), 1);
        // A cache hit still requires independent report signature verification.
        let bytes = super::fetch(&server.url, &invalid, &ProcessorGeneration::Milan)
            .await
            .unwrap();
        let cert = Certificate::from(X509::from_der(&bytes).unwrap());
        assert!((&cert, &invalid).verify().is_err());
        assert_eq!(server.count(), 1);
    }

    #[tokio::test]
    async fn shared_download_errors_preserve_the_source_type() {
        let server = Server::with_bodies(vec![(200, "", b"not DER".to_vec())]).await;
        let error = fetch(&server.url).await.unwrap_err();
        assert!(error
            .chain()
            .any(|cause| cause.downcast_ref::<openssl::error::ErrorStack>().is_some()));
    }

    #[tokio::test]
    async fn expired_certificates_are_downloaded_again() {
        let server = Server::new(vec![(200, "")]).await;
        let cache = Cache::builder()
            .max_capacity(1)
            .time_to_live(Duration::from_millis(20))
            .build();
        let report = AttestationReport::from_bytes(REPORT).unwrap();
        fetch_cached(&cache, &server.url, &report, &ProcessorGeneration::Milan)
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        fetch_cached(&cache, &server.url, &report, &ProcessorGeneration::Milan)
            .await
            .unwrap();
        assert_eq!(server.count(), 2);
    }
}
