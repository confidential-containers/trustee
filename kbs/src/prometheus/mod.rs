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
