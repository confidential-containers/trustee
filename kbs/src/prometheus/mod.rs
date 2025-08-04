// Copyright (c) 2025 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

use lazy_static::lazy_static;
use prometheus::{
    Counter, CounterVec, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder,
};

macro_rules! make_counter {
    ($name:literal , $help:literal $(,)?) => {{
        let opts = Opts::new($name, $help);
        Counter::with_opts(opts).unwrap()
    }};
}

macro_rules! make_counter_vec {
    ($name:literal, $help:literal, $labels:expr $(,)?) => {{
        let opts = Opts::new($name, $help);
        CounterVec::new(opts, &$labels).unwrap()
    }};
}

macro_rules! make_histogram {
    ($name:literal, $help:literal, $buckets:expr $(,)?) => {{
        let opts = HistogramOpts::new($name, $help).buckets($buckets);
        Histogram::with_opts(opts).unwrap()
    }};
}

lazy_static! {
    /// Resource Path Read Metrics
    pub(crate) static ref RESOURCE_READS_TOTAL: CounterVec = make_counter_vec!{
        "resource_reads_total", "KBS resource read count", ["resource_path"]
    };

    /// Resource Path Write Metrics
    pub(crate) static ref RESOURCE_WRITES_TOTAL: CounterVec = make_counter_vec!{
        "resource_writes_total", "KBS resource write count", ["resource_path"]
    };

    /// KBS Web Server Requests Metrics
    pub(crate) static ref REQUEST_TOTAL: Counter = make_counter!{
        "http_requests_total",
        "Total HTTP requests count",
    };

    /// KBS Web Server Requests Metrics
    pub(crate) static ref REQUEST_DURATION: Histogram = make_histogram!{
        "http_request_duration_seconds",
        "Distribution of request handling duration",
        vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.5, 1.0],
    };

    /// KBS Web Server Request Sizes
    pub(crate) static ref REQUEST_SIZES: Histogram = make_histogram!{
        "http_request_size_bytes",
        "Distribution of request body sizes",
        prometheus::exponential_buckets(32.0, 4.0, 5).unwrap(),
    };

    /// KBS Web Server Response Sizes
    pub(crate) static ref RESPONSE_SIZES: Histogram = make_histogram!{
        "http_response_size_bytes",
        "Distribution of response body sizes",
        prometheus::exponential_buckets(32.0, 4.0, 5).unwrap(),
    };

    /// KBS Policy Evaluations Total
    pub(crate) static ref KBS_POLICY_EVALS: Counter = make_counter!{
        "kbs_policy_evaluations_total",
        "Total count of KBS policy evaluations",
    };

    /// KBS Policy Approvals Total
    pub(crate) static ref KBS_POLICY_APPROVALS: Counter = make_counter!{
        "kbs_policy_approvals_total",
        "Total count of requests approved by KBS policy",
    };

    /// KBS Policy Violations Total
    pub(crate) static ref KBS_POLICY_VIOLATIONS: Counter = make_counter!{
        "kbs_policy_violations_total",
        "Total count of requests denied by KBS policy",
    };

    /// KBS Policy Errors Total
    pub(crate) static ref KBS_POLICY_ERRORS: Counter = make_counter!{
        "kbs_policy_errors_total",
        "Total count of errors during KBS evaluation",
    };

    /// KBS Attestation Requests Total
    pub(crate) static ref ATTESTATION_REQUESTS: Counter = make_counter!{
        "attestation_requests_total",
        "Total count of attestation requests",
    };

    /// KBS Attestation Successes Total
    pub(crate) static ref ATTESTATION_SUCCESSES: CounterVec = make_counter_vec!{
        "attestation_successes_total",
        "Total count of attestation successes",
        ["tee_type"],
    };

    /// KBS Attestation Failures Total
    pub(crate) static ref ATTESTATION_FAILURES: CounterVec = make_counter_vec!{
        "attestation_failures_total",
        "Total count of attestation failures",
        ["tee_type"],
    };

    /// KBS Attestation Errors Total
    pub(crate) static ref ATTESTATION_ERRORS: Counter = make_counter!{
        "attestation_errors_total",
        "Total count of errors during attestation processing",
    };

    /// KBS Auth Requests Total
    pub(crate) static ref AUTH_REQUESTS: Counter = make_counter!{
        "auth_requests_total",
        "Total count of auth requests",
    };

    /// KBS Auth Successes Total
    pub(crate) static ref AUTH_SUCCESSES: Counter = make_counter!{
        "auth_successes_total",
        "Total count of successfully authenticated requests",
    };

    /// KBS Auth Errors Total
    pub(crate) static ref AUTH_ERRORS: Counter = make_counter!{
        "auth_errors_total",
        "Total count of errors during auth processing",
    };

    /// KBS Web Server Active Connections
    pub(crate) static ref ACTIVE_CONNECTIONS: Gauge = {
        let opts = Opts::new(
            "http_active_connections",
            "Count of HTTP connections being processed at the moment",
        );
        Gauge::with_opts(opts).unwrap()
    };

    /// KBS Build Info
    pub(crate) static ref BUILD_INFO: Gauge = {
        let opts = Opts::new(
                "build_info",
                "KBS binary build info",
            )
            .const_labels(std::collections::HashMap::from([
                ("version".to_owned(), env!("CARGO_PKG_VERSION").to_owned()),
                ("git_hash".to_owned(), env!("KBS_GIT_HASH").to_owned()),
                ("build_date".to_owned(), env!("KBS_BUILD_DATE").to_owned())
            ]));
        Gauge::with_opts(opts).unwrap()
    };

    /// Prometheus instance to get the metrics
    static ref INSTANCE: Registry = {
        let registry = Registry::default();

        registry
            .register(Box::new(RESOURCE_READS_TOTAL.clone()))
            .unwrap();

        registry.register(Box::new(RESOURCE_WRITES_TOTAL.clone())).unwrap();
        registry.register(Box::new(REQUEST_TOTAL.clone())).unwrap();
        registry.register(Box::new(REQUEST_DURATION.clone())).unwrap();
        registry.register(Box::new(REQUEST_SIZES.clone())).unwrap();
        registry.register(Box::new(RESPONSE_SIZES.clone())).unwrap();
        registry.register(Box::new(KBS_POLICY_EVALS.clone())).unwrap();
        registry.register(Box::new(KBS_POLICY_APPROVALS.clone())).unwrap();
        registry.register(Box::new(KBS_POLICY_VIOLATIONS.clone())).unwrap();
        registry.register(Box::new(KBS_POLICY_ERRORS.clone())).unwrap();
        registry.register(Box::new(ATTESTATION_REQUESTS.clone())).unwrap();
        registry.register(Box::new(ATTESTATION_SUCCESSES.clone())).unwrap();
        registry.register(Box::new(ATTESTATION_FAILURES.clone())).unwrap();
        registry.register(Box::new(ATTESTATION_ERRORS.clone())).unwrap();
        registry.register(Box::new(AUTH_REQUESTS.clone())).unwrap();
        registry.register(Box::new(AUTH_SUCCESSES.clone())).unwrap();
        registry.register(Box::new(AUTH_ERRORS.clone())).unwrap();
        registry.register(Box::new(ACTIVE_CONNECTIONS.clone())).unwrap();
        registry.register(Box::new(BUILD_INFO.clone())).unwrap();

        registry
    };
}

pub(crate) fn export_metrics() -> Result<String, prometheus::Error> {
    let mut metrics_buffer = String::new();
    TextEncoder::new().encode_utf8(&INSTANCE.gather(), &mut metrics_buffer)?;
    Ok(metrics_buffer)
}

#[cfg(test)]
mod tests {
    use crate::prometheus::{
        export_metrics, REQUEST_DURATION, REQUEST_SIZES, REQUEST_TOTAL, RESOURCE_READS_TOTAL,
        RESOURCE_WRITES_TOTAL, RESPONSE_SIZES,
    };

    #[test]
    fn matrics_recording() {
        RESOURCE_READS_TOTAL
            .with_label_values(&["default/key/read"])
            .inc();
        RESOURCE_READS_TOTAL
            .with_label_values(&["default/key/read"])
            .inc();
        RESOURCE_WRITES_TOTAL
            .with_label_values(&["default/key/write"])
            .inc();
        REQUEST_TOTAL.inc();
        REQUEST_TOTAL.inc();
        REQUEST_TOTAL.inc();
        REQUEST_DURATION.observe(10.0);
        REQUEST_SIZES.observe(1024.0);
        RESPONSE_SIZES.observe(2048.0);

        let metrics = export_metrics().unwrap();
        assert!(metrics.contains("resource_reads_total{resource_path=\"default/key/read\"} 2"));
        assert!(metrics.contains("resource_writes_total{resource_path=\"default/key/write\"} 1"));
        assert!(metrics.contains("resource_writes_total{resource_path=\"default/key/write\"} 1"));
        assert!(metrics.contains("http_requests_total 3"));
        assert!(metrics.contains("http_request_duration_seconds_count 1"));
        assert!(metrics.contains("http_request_duration_seconds_sum 10"));
        assert!(metrics.contains("http_request_size_bytes_sum 1024"));
        assert!(metrics.contains("http_request_size_bytes_count 1"));
        assert!(metrics.contains("http_response_size_bytes_sum 2048"));
        assert!(metrics.contains("http_response_size_bytes_count 1"));
    }
}
