// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! reference value for RVPS

use anyhow::{anyhow, Result};
use chrono::{DateTime, Months, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Deserializer, Serialize};
use std::time::SystemTime;

/// Default version of ReferenceValue
pub const REFERENCE_VALUE_VERSION: &str = "0.1.0";
pub const MONTHS_BEFORE_EXPIRATION: u32 = 12;

/// Helper to deserialize an expired time
fn primitive_date_time_from_str<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<DateTime<Utc>, D::Error> {
    let s = <Option<&str>>::deserialize(d)?
        .ok_or_else(|| serde::de::Error::invalid_length(0, &"<TIME>"))?;

    let ndt = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
        .map_err(|err| serde::de::Error::custom::<String>(err.to_string()))?;

    Ok(DateTime::from_naive_utc_and_offset(ndt, Utc))
}

/// The ReferenceValue struct contains metadata about the RV
/// as well as the value itself.
/// This struct will be stored in one of the RVPS's storage backends.
/// This is the internal representation of reference values,
/// which is not intended to exactly match the RATS specification
/// or the RVPS API.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReferenceValue {
    /// Since the reference values will be written to storage,
    /// keep track of the version in case the RVPS implementation
    /// is updated.
    #[serde(default = "default_version")]
    pub version: String,
    pub name: String,
    /// The reference value will be invalid after its expiration time.
    /// By default the expiration time is 12 months from when
    /// the reference value is created. This can be set
    /// dynamically by extractors.
    #[serde(deserialize_with = "primitive_date_time_from_str")]
    pub expiration: DateTime<Utc>,
    /// The reference value can be any type suported by
    /// serde_json, including nested types.
    pub value: serde_json::Value,
}

/// Set the default version for ReferenceValue
fn default_version() -> String {
    REFERENCE_VALUE_VERSION.into()
}

impl ReferenceValue {
    /// Create a new `ReferenceValue`, the `expiration`
    /// field's nanosecond will be set to 0. This avoid
    /// a rare bug that when the nanosecond of the time
    /// is not 0, the test case will fail.
    pub fn new() -> Result<Self> {
        Ok(ReferenceValue {
            version: REFERENCE_VALUE_VERSION.into(),
            name: String::new(),
            expiration: Utc::now()
                .with_nanosecond(0)
                .and_then(|t| t.checked_add_months(Months::new(MONTHS_BEFORE_EXPIRATION)))
                .ok_or_else(|| anyhow!("Failed to set time."))?,
            value: serde_json::Value::Null,
        })
    }

    /// Set version of the ReferenceValue.
    pub fn set_version(mut self, version: &str) -> Self {
        self.version = version.into();
        self
    }

    /// Get version of the ReferenceValue.
    pub fn version(&self) -> &String {
        &self.version
    }

    /// Set expired time of the ReferenceValue.
    pub fn set_expiration(mut self, expiration: DateTime<Utc>) -> Self {
        self.expiration = expiration
            .with_nanosecond(0)
            .expect("Set nanosecond failed.");
        self
    }

    pub fn set_value(mut self, value: serde_json::Value) -> Self {
        self.value = value;

        self
    }

    pub fn value(self) -> serde_json::Value {
        self.value
    }

    /// Check whether reference value is expired
    pub fn expired(&self) -> bool {
        let now: DateTime<Utc> = DateTime::from(SystemTime::now());

        now > self.expiration
    }

    /// Set artifact name for Reference Value
    pub fn set_name(mut self, name: &str) -> Self {
        self.name = name.into();
        self
    }

    /// Get artifact name of the ReferenceValue.
    pub fn name(&self) -> &String {
        &self.name
    }
}

/// Trusted Digest is what RVPS actually delivered to
/// AS, it will include:
/// * `name`: The name of the artifact, e.g., `linux-1.1.1`
/// * `hash_values`: digests that have been verified and can
///   be trusted, so we can refer them as `trusted digests`.
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq, Eq)]
pub struct TrustedDigest {
    /// The resource name.
    pub name: String,
    /// The reference hash values, base64 coded.
    pub hash_values: Vec<String>,
}

#[cfg(test)]
mod test {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::ReferenceValue;

    #[test]
    fn reference_value_serialize() {
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_version("1.0.0")
            .set_name("artifact")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .set_value(serde_json::Value::String("abc".to_string()));

        assert_eq!(rv.version(), "1.0.0");

        let rv_json = json!({
            "expiration": "1970-01-01T00:00:00Z",
            "name": "artifact",
            "version": "1.0.0",
            "value": "abc"
        });

        let serialized_rf = serde_json::to_value(&rv).unwrap();
        assert_eq!(serialized_rf, rv_json);
    }

    #[test]
    fn reference_value_deserialize() {
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed.")
            .set_version("1.0.0")
            .set_name("artifact")
            .set_expiration(Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap())
            .set_value(serde_json::Value::String("abcd".to_string()));

        assert_eq!(rv.version(), "1.0.0");
        let rv_json = r#"{
            "expiration": "1970-01-01T00:00:00Z",
            "name": "artifact",
            "version": "1.0.0",
            "value": "abcd"
        }"#;
        let deserialized_rf: ReferenceValue = serde_json::from_str(&rv_json).unwrap();
        assert_eq!(deserialized_rf, rv);
    }
}
