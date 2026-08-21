// Copyright (c) 2026 by Trustee Contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! SPIRE plugin.
//!
//! Provides SPIFFE SVIDs to attested workloads via the SPIRE Delegated
//! Identity API.
//!
//! This plugin integrates with an existing SPIRE agent/server.
//! The plugin provides selectors to the SPIRE agent and gets an SVID
//! in return.
//!
//! Selectors are derived from validated-identifiers, which are extracted
//! from hw evidence and init-data plaintext in the attestation service policy.
//! Selectors can match existing k8s selectors or be issued as Trustee-specific
//! selectors.
//!
//! For now, only x509 is supported.
//!
//! - `GET x509-svid`: an X.509-SVID for the calling workload.
//! - `GET x509-bundles`: the current X.509 trust bundle(s).
//!
//! See `kbs/docs/plugins/spire.md` for setup and configuration details.

use std::collections::HashMap;

use actix_web::http::Method;
use anyhow::{bail, Context, Error, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use spire_api::selectors::Selector;
use spire_api::{DelegateAttestationRequest, DelegatedIdentityClient};
use tracing::{debug, error, warn};

use crate::plugins::plugin_manager::ClientPlugin;

fn default_k8s_selector_prefix() -> String {
    "k8s".to_string()
}

fn default_trustee_selector_prefix() -> String {
    "trustee".to_string()
}

// Pod-level selector key names that are provided by the SPIRE
// workload attestor. Plugin handles these selectors specially.
const KNOWN_K8S_SELECTOR_KEYS: &[&str] = &[
    "ns",
    "ns-label",
    "sa",
    "node-name",
    "pod-label",
    "pod-owner",
    "pod-owner-uid",
    "pod-uid",
    "pod-name",
    "pod-image",
    "pod-image-count",
    "pod-init-image",
    "pod-init-image-count",
];

fn default_attested_selector_value() -> String {
    "true".to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct SpirePluginConfig {
    /// Filesystem path to the SPIRE Agent admin (Delegated Identity API)
    /// Unix domain socket, e.g. `/run/spire/sockets/admin.sock`.
    pub admin_socket_path: String,

    /// Value used for the always-added `trustee:<value>` marker selector.
    #[serde(default = "default_attested_selector_value")]
    pub attested_selector_value: String,

    /// SPIRE selector type used for `validated_identifiers` keys that match a
    /// selector name SPIRE's built-in k8s workload attestor actually produces
    /// (see `KNOWN_K8S_SELECTOR_KEYS`). By default, this will produce some
    /// selectors that are identifical to what the k8s attestor would produce.
    /// If this is not desirable, specify your own selector type.
    #[serde(default = "default_k8s_selector_prefix")]
    pub k8s_selector_prefix: String,

    /// Selector type for selectors that are not provided by the SPIRE k8s
    /// workload attestor. These are Trustee-specific selectors. By default
    /// the type is "trustee".
    #[serde(default = "default_trustee_selector_prefix")]
    pub trustee_selector_prefix: String,
}

impl TryFrom<SpirePluginConfig> for SpirePlugin {
    type Error = Error;

    fn try_from(config: SpirePluginConfig) -> Result<Self> {
        Ok(SpirePlugin {
            admin_socket_path: config.admin_socket_path,
            attested_selector_value: config.attested_selector_value,
            k8s_selector_prefix: config.k8s_selector_prefix,
            trustee_selector_prefix: config.trustee_selector_prefix,
        })
    }
}

/// SPIRE plugin object.
#[derive(Debug)]
pub struct SpirePlugin {
    admin_socket_path: String,
    attested_selector_value: String,
    k8s_selector_prefix: String,
    trustee_selector_prefix: String,
}

#[derive(Debug, Serialize)]
pub struct SpireSvidResponse {
    pub spiffe_id: String,
    /// DER-encoded X.509 certificate chain, leaf first.
    pub cert_chain: Vec<Vec<u8>>,
    /// DER-encoded PKCS#8 private key.
    pub private_key: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SpireX509BundlesResponse {
    /// Map of trust domain names to DER x509 trust bundles
    pub bundles: HashMap<String, Vec<Vec<u8>>>,
}

fn parse_selector(
    key: &str,
    value: &Value,
    k8s_prefix: &str,
    trustee_prefix: &str,
) -> Option<Selector> {
    let selector_type = if KNOWN_K8S_SELECTOR_KEYS.contains(&key) {
        k8s_prefix
    } else {
        trustee_prefix
    };

    // Parse as string without quotes
    let value = match value {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Null | Value::Array(_) | Value::Object(_) => return None,
    };

    Some(Selector::Generic((
        selector_type.to_string(),
        format!("{key}:{value}"),
    )))
}

/// Turns `ear.trustee.identifiers/validated` object into SPIRE
/// selectors.
fn selectors_from_validated_identifiers(
    validated: Option<&Value>,
    attested_selector_value: &str,
    k8s_prefix: &str,
    trustee_prefix: &str,
) -> Vec<Selector> {
    let mut selectors = Vec::new();

    if let Some(Value::Object(map)) = validated {
        for (key, value) in map {
            match value {
                // If we find an array, make a selector for each element.
                Value::Array(items) => {
                    selectors.extend(
                        items.iter().filter_map(|item| {
                            parse_selector(key, item, k8s_prefix, trustee_prefix)
                        }),
                    );
                }
                value => selectors.extend(parse_selector(key, value, k8s_prefix, trustee_prefix)),
            }
        }
    }

    // Add the default selector, which is always present.
    selectors.push(Selector::Generic((
        trustee_prefix.to_string(),
        attested_selector_value.to_string(),
    )));

    selectors
}

impl SpirePlugin {
    async fn connect(&self) -> Result<DelegatedIdentityClient> {
        let endpoint = format!("unix://{}", self.admin_socket_path);

        DelegatedIdentityClient::connect_to(&endpoint)
            .await
            .inspect_err(|e| {
                error!(
                    admin_socket_path = %self.admin_socket_path,
                    endpoint = %endpoint,
                    error = %e,
                    "SPIRE plugin: failed to connect to the SPIRE Agent admin socket"
                );
            })
            .context("Failed to connect to the SPIRE Agent admin socket")
    }

    async fn fetch_svid(&self, selectors: Vec<Selector>) -> Result<SpireSvidResponse> {
        debug!(?selectors, "SPIRE plugin: fetching X.509-SVID");

        let client = self.connect().await?;

        let svid = client
            .fetch_x509_svid(DelegateAttestationRequest::Selectors(selectors.clone()))
            .await
            .inspect_err(|e| {
                error!(
                    ?selectors,
                    error = %e,
                     "failed to fetch an X.509-SVID from the SPIRE Agent"
                );
            })
            .context("Failed to fetch an X.509-SVID from the SPIRE Agent")?;

        Ok(SpireSvidResponse {
            spiffe_id: svid.spiffe_id().to_string(),
            cert_chain: svid
                .cert_chain()
                .iter()
                .map(|cert| cert.as_bytes().to_vec())
                .collect(),
            private_key: svid.private_key().as_bytes().to_vec(),
        })
    }

    /// Fetches the current trust bundle(s) - own trust domain plus any
    /// federated ones - with no selectors (see `SpireX509BundlesResponse`).
    async fn fetch_bundles(&self) -> Result<SpireX509BundlesResponse> {
        debug!("SPIRE plugin: fetching X.509 trust bundles");
        let client = self.connect().await?;

        let bundle_set = client
            .fetch_x509_bundles()
            .await
            .inspect_err(|e| {
                error!(
                    error = %e,
                    "SPIRE plugin: failed to fetch X.509 trust bundles from the SPIRE Agent"
                );
            })
            .context("Failed to fetch X.509 trust bundles from the SPIRE Agent")?;

        let bundles = bundle_set
            .iter()
            .map(|(trust_domain, bundle)| {
                let der_authorities = bundle
                    .authorities()
                    .iter()
                    .map(|cert| cert.as_bytes().to_vec())
                    .collect();
                (trust_domain.to_string(), der_authorities)
            })
            .collect();

        Ok(SpireX509BundlesResponse { bundles })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for SpirePlugin {
    async fn handle(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        path: &[&str],
        method: &Method,
        _init_data: Option<&Value>,
        validated_identifiers: Option<&Value>,
    ) -> Result<Vec<u8>> {
        if method.as_str() != "GET" {
            bail!("Illegal HTTP method. Only GET is supported");
        }

        debug!(?path, "SPIRE plugin: handling request");

        match path {
            ["x509-svid"] => {
                let selectors = selectors_from_validated_identifiers(
                    validated_identifiers,
                    &self.attested_selector_value,
                    &self.k8s_selector_prefix,
                    &self.trustee_selector_prefix,
                );

                let response = self.fetch_svid(selectors).await?;
                Ok(serde_json::to_vec(&response)?)
            }
            ["x509-bundles"] => {
                let response = self.fetch_bundles().await?;
                Ok(serde_json::to_vec(&response)?)
            }
            _ => {
                warn!(?path, "SPIRE plugin: request to unsupported path");
                bail!("Illegal path. Only x509 SVIDs and bundles are supported.")
            }
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        // There is no admin interface.
        Ok(false)
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &[&str],
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn as_generic_tuples(selectors: Vec<Selector>) -> Vec<(String, String)> {
        selectors
            .into_iter()
            .map(|s| match s {
                Selector::Generic(tuple) => tuple,
                other => panic!("unexpected selector variant: {other:?}"),
            })
            .collect()
    }

    #[test]
    fn generic_mapping_with_arrays_and_single_values() {
        // None of these keys are known k8s workload attestor selector
        // names, so they should all end up typed `trustee`, not `k8s`.
        let validated = json!({
            "container_images": ["bitnami/nginx:latest"],
            "container_uids": [1001, 65535],
            "single_value": "hello",
        });

        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            Some(&validated),
            "true",
            "k8s",
            "trustee",
        ));

        assert_eq!(rendered.len(), 5);
        assert!(rendered.contains(&(
            "trustee".to_string(),
            "container_images:bitnami/nginx:latest".to_string()
        )));
        assert!(rendered.contains(&("trustee".to_string(), "container_uids:1001".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "container_uids:65535".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "single_value:hello".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "true".to_string())));
    }

    #[test]
    fn known_k8s_selector_keys_are_typed_k8s() {
        let validated = json!({
            "ns": "default",
            "sa": "my-service-account",
            "pod-uid": ["11111111-1111-1111-1111-111111111111"],
        });

        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            Some(&validated),
            "true",
            "k8s",
            "trustee",
        ));

        assert_eq!(rendered.len(), 4);
        assert!(rendered.contains(&("k8s".to_string(), "ns:default".to_string())));
        assert!(rendered.contains(&("k8s".to_string(), "sa:my-service-account".to_string())));
        assert!(rendered.contains(&(
            "k8s".to_string(),
            "pod-uid:11111111-1111-1111-1111-111111111111".to_string()
        )));
        assert!(rendered.contains(&("trustee".to_string(), "true".to_string())));
    }

    #[test]
    fn pod_image_array_yields_one_selector_per_image() {
        // Per the k8s workload attestor spec, `pod-image` selector *value*
        // is always a single image - a pod with multiple container images
        // is represented as multiple `pod-image` selectors, not one
        // selector holding a list.
        let validated = json!({
            "pod-image": ["bitnami/nginx:latest", "docker.io/envoyproxy/envoy-alpine:v1.16.0"],
            "pod-image-count": 2,
        });

        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            Some(&validated),
            "true",
            "k8s",
            "trustee",
        ));

        assert_eq!(rendered.len(), 4);
        assert!(rendered.contains(&(
            "k8s".to_string(),
            "pod-image:bitnami/nginx:latest".to_string()
        )));
        assert!(rendered.contains(&(
            "k8s".to_string(),
            "pod-image:docker.io/envoyproxy/envoy-alpine:v1.16.0".to_string()
        )));
        assert!(rendered.contains(&("k8s".to_string(), "pod-image-count:2".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "true".to_string())));
    }

    #[test]
    fn mixed_known_and_unknown_keys_get_different_selector_types() {
        let validated = json!({
            "ns": "default",
            "custom_claim": "some-value",
        });

        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            Some(&validated),
            "true",
            "k8s",
            "trustee",
        ));

        assert_eq!(rendered.len(), 3);
        assert!(rendered.contains(&("k8s".to_string(), "ns:default".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "custom_claim:some-value".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "true".to_string())));
    }

    #[test]
    fn configurable_attested_selector_value() {
        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            None, "prod-kbs", "k8s", "trustee",
        ));
        assert_eq!(
            rendered,
            vec![("trustee".to_string(), "prod-kbs".to_string())]
        );
    }

    #[test]
    fn configurable_selector_prefixes() {
        let validated = json!({"ns": "default", "custom_claim": "some-value"});
        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            Some(&validated),
            "true",
            "kubernetes",
            "attested-by-trustee",
        ));
        assert_eq!(rendered.len(), 3);
        assert!(rendered.contains(&("kubernetes".to_string(), "ns:default".to_string())));
        assert!(rendered.contains(&(
            "attested-by-trustee".to_string(),
            "custom_claim:some-value".to_string()
        )));
        assert!(rendered.contains(&("attested-by-trustee".to_string(), "true".to_string())));
    }

    #[test]
    fn missing_validated_identifiers_yields_only_the_marker_selector() {
        let selectors = selectors_from_validated_identifiers(None, "true", "k8s", "trustee");
        assert_eq!(selectors.len(), 1);
    }

    #[test]
    fn non_object_validated_identifiers_yields_only_the_marker_selector() {
        let selectors = selectors_from_validated_identifiers(
            Some(&json!(["not", "an", "object"])),
            "true",
            "k8s",
            "trustee",
        );
        assert_eq!(selectors.len(), 1);
    }

    #[test]
    fn null_and_nested_values_are_skipped() {
        let validated = json!({
            "ignored_null": null,
            "ignored_nested": {"a": "b"},
            "kept": "value",
        });
        let rendered = as_generic_tuples(selectors_from_validated_identifiers(
            Some(&validated),
            "true",
            "k8s",
            "trustee",
        ));
        assert_eq!(rendered.len(), 2);
        assert!(rendered.contains(&("trustee".to_string(), "kept:value".to_string())));
        assert!(rendered.contains(&("trustee".to_string(), "true".to_string())));
    }
}
