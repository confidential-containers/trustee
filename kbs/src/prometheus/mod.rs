// Copyright (c) 2025 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

use lazy_static::lazy_static;
use prometheus::{Counter, CounterVec, Histogram, HistogramOpts, Opts, Registry, TextEncoder};

lazy_static! {
    /// Resource Path Read Metrics
    pub(crate) static ref RESOURCE_READS_TOTAL: CounterVec = {
        let reads_opts = Opts::new("resource_reads_total", "KBS resource read count");
        CounterVec::new(reads_opts, &["resource_path"]).unwrap()
    };

    /// Resource Path Write Metrics
    pub(crate) static ref RESOURCE_WRITES_TOTAL: CounterVec = {
        let writes_opts = Opts::new("resource_writes_total", "KBS resource write count");
        CounterVec::new(writes_opts, &["resource_path"]).unwrap()
    };

    /// KBS Web Server Requests Metrics
    pub(crate) static ref REQUEST_TOTAL: Counter = {
        let requests_opts = Opts::new(
            "http_requests_total",
            "Total HTTP requests count",
        );
        Counter::with_opts(requests_opts).unwrap()
    };

    /// KBS Web Server Requests Metrics
    pub(crate) static ref REQUEST_DURATION: Histogram = {
        let requests_duration_opts = HistogramOpts::new(
                "http_request_duration_seconds",
                "Distribution of request handling duration",
        ).buckets(vec![0.0005, 0.001, 0.005, 0.01, 0.05, 0.5, 1.0]);
        Histogram::with_opts(requests_duration_opts).unwrap()
    };

    /// KBS Web Server Request Sizes
    pub(crate) static ref REQUEST_SIZES: Histogram = {
        let request_sizes_opts = HistogramOpts::new(
                "http_request_size_bytes",
                "Distribution of request body sizes",
            )
            .buckets(prometheus::exponential_buckets(32.0, 4.0, 5).unwrap());
        Histogram::with_opts(request_sizes_opts).unwrap()
    };

    /// KBS Web Server Response Sizes
    pub(crate) static ref RESPONSE_SIZES: Histogram = {
        let response_sizes_opts = HistogramOpts::new(
                "http_response_size_bytes",
                "Distribution of response body sizes",
            )
            .buckets(prometheus::exponential_buckets(32.0, 4.0, 5).unwrap());
        Histogram::with_opts(response_sizes_opts).unwrap()
    };

    /// KBS Policy Evaluations Total
    pub(crate) static ref KBS_POLICY_EVALS: Counter = {
        let opts = Opts::new(
            "kbs_policy_evaluations_total",
            "Total count of KBS policy evaluations",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Policy Approvals Total
    pub(crate) static ref KBS_POLICY_APPROVALS: Counter = {
        let opts = Opts::new(
            "kbs_policy_approvals_total",
            "Total count of requests approved by KBS policy",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Policy Violations Total
    pub(crate) static ref KBS_POLICY_VIOLATIONS: Counter = {
        let opts = Opts::new(
            "kbs_policy_violations_total",
            "Total count of requests denied by KBS policy",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Policy Errors Total
    pub(crate) static ref KBS_POLICY_ERRORS: Counter = {
        let opts = Opts::new(
            "kbs_policy_errors_total",
            "Total count of errors during KBS evaluation",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Attestation Requests Total
    pub(crate) static ref ATTESTATION_REQUESTS: Counter = {
        let opts = Opts::new(
            "attestation_requests_total",
            "Total count of attestation requests",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Attestation Successes Total
    pub(crate) static ref ATTESTATION_SUCCESSES: CounterVec = {
        let opts = Opts::new(
            "attestation_successes_total",
            "Total count of attestation successes",
        );
        CounterVec::new(opts, &["tee_type"]).unwrap()
    };

    /// KBS Attestation Failures Total
    pub(crate) static ref ATTESTATION_FAILURES: CounterVec = {
        let opts = Opts::new(
            "attestation_failures_total",
            "Total count of attestation failures",
        );
        CounterVec::new(opts, &["tee_type"]).unwrap()
    };

    /// KBS Attestation Errors Total
    pub(crate) static ref ATTESTATION_ERRORS: Counter = {
        let opts = Opts::new(
            "attestation_errors_total",
            "Total count of errors during attestation processing",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Auth Requests Total
    pub(crate) static ref AUTH_REQUESTS: Counter = {
        let opts = Opts::new(
            "auth_requests_total",
            "Total count of auth requests",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Auth Successes Total
    pub(crate) static ref AUTH_SUCCESSES: Counter = {
        let opts = Opts::new(
            "auth_successes_total",
            "Total count of successfully authenticated requests",
        );
        Counter::with_opts(opts).unwrap()
    };

    /// KBS Auth Errors Total
    pub(crate) static ref AUTH_ERRORS: Counter = {
        let opts = Opts::new(
            "auth_errors_total",
            "Total count of errors during auth processing",
        );
        Counter::with_opts(opts).unwrap()
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
