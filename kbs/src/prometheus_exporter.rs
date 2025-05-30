// Copyright (c) 2025 Red Hat
//
// SPDX-License-Identifier: Apache-2.0
//

use lazy_static::lazy_static;
use prometheus::{core::Collector, TextEncoder};
use std::sync::Mutex;

lazy_static! {
    pub static ref instance: Mutex<PrometheusExporter> = Mutex::new(PrometheusExporter::new());
}

#[derive(Clone, Default)]
pub struct PrometheusExporter {
    registry: prometheus::Registry,
}

impl PrometheusExporter {
    fn new() -> Self {
        Self::default()
    }

    // This function is idempotent - trying to register a metric that's
    // already registered is not an error.  This doesn't matter much during
    // normal usage in a KBS binary, it does however in tests which create and
    // tear down KBS's HTTP server repeatedly.
    pub fn register(&self, metric: Box<dyn Collector>) -> Result<(), prometheus::Error> {
        match self.registry.register(metric) {
            Ok(_) => Ok(()),
            Err(err) => {
                if let prometheus::Error::AlreadyReg = err {
                    Ok(())
                } else {
                    Err(err)
                }
            }
        }
    }

    pub fn unregister(&self, metric: Box<dyn Collector>) -> Result<(), prometheus::Error> {
        // Ideally, unregistration would be idempotent just like registration.
        // However, prometheus::Error unfortunately doesn't have a dedicated
        // variant for an attempt to unregister a metric that hasn't been
        // registered and this type of error reported via the generic Msg
        // variant instead.  This makes it impossible to handle it here
        // cleanly.
        self.registry.unregister(metric)?;
        Ok(())
    }

    pub fn export_metrics(&self) -> Result<String, prometheus::Error> {
        let mut metrics_buffer = String::new();
        TextEncoder::new().encode_utf8(&self.registry.gather(), &mut metrics_buffer)?;
        Ok(metrics_buffer)
    }
}
