extern crate serde;

#[macro_use]
extern crate log;

extern crate strum;

#[macro_use]
extern crate strum_macros;

pub mod policy_engine;
pub mod types;
pub mod verifier;

use anyhow::{Context, Result};
use policy_engine::opa;
use serde_json::Value;
use std::collections::HashMap;
use std::str::FromStr;
use types::{AttestationResults, Evidence, TEE};

#[macro_export]
macro_rules! default_policy {
    () => {
        "../default_policy.rego"
    };
}

#[derive(Debug)]
pub struct Service {
    pub attestation: Attestation,
}

impl Default for Service {
    fn default() -> Self {
        Self::new()
    }
}

impl Service {
    /// Create a new attestation service's instance.
    pub fn new() -> Self {
        Self {
            attestation: Attestation::default(),
        }
    }

    /// Attest the received Evidence by the attestation service instance.
    pub async fn attestation(
        &self,
        evidence: &str,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<String> {
        self.attestation
            .evaluate(evidence, policy, reference_data)
            .await
    }

    /// Get the specific TEE's Open Policy Agent default policy file.
    pub fn opa_test(
        &self,
        policy_content: String,
        reference_content: String,
        input_content: String,
    ) -> Result<String> {
        opa::evaluate(policy_content, reference_content, input_content)
    }

    /// Get the specific TEE's Open Policy Agent default policy file.
    pub async fn default_policy(&self) -> Result<String> {
        self.attestation.default_policy()
    }
}

#[derive(Debug, Default)]
pub struct Attestation {}

impl Attestation {
    pub async fn evaluate(
        &self,
        evidence: &str,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<String> {
        let evidence =
            serde_json::from_str::<Evidence>(evidence).context("Deserialize Evidence failed.")?;
        let verifier = TEE::from_str(&evidence.tee)?.to_verifier()?;

        let claims_from_tee_evidence = match verifier.evaluate(&evidence).await {
            Ok(claims) => claims,
            Err(e) => {
                let attestation_results = serde_json::to_string(&AttestationResults::new(
                    evidence.tee.clone(),
                    false,
                    Some(format!("Verifier evaluate failed: {:?}", e)),
                    None,
                    None,
                ))?;
                return Ok(attestation_results);
            }
        };

        let opa_input_data = serde_json::to_string(&claims_from_tee_evidence)?;

        let opa_policy = policy.unwrap_or_else(|| std::include_str!(default_policy!()).to_string());
        let opa_reference_data = match reference_data {
            Some(data) => data,
            None => {
                let mut data: HashMap<String, Vec<String>> = HashMap::new();
                let claims_map: HashMap<String, serde_json::Value> =
                    serde_json::from_value(claims_from_tee_evidence.clone())?;
                for key in claims_map.keys() {
                    data.insert(key.to_string(), Vec::new());
                }
                serde_json::json!({ "reference": data }).to_string()
            }
        };
        // TODO: Update the reference data with RVPS.

        let opa_output = opa::evaluate(opa_policy, opa_reference_data, opa_input_data)?;
        let v_opa_output: Value = serde_json::from_str(&opa_output)?;

        let attestation_results = AttestationResults::new(
            evidence.tee.clone(),
            v_opa_output["allow"].as_bool().unwrap_or(false),
            None,
            Some(opa_output),
            Some(serde_json::to_string(&claims_from_tee_evidence)?),
        );

        let results = serde_json::to_string(&attestation_results)?;

        debug!("Attestation Results: {:?}", &attestation_results);
        Ok(results)
    }

    pub fn default_policy(&self) -> Result<String> {
        Ok(std::include_str!(default_policy!()).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::Service;
    use base64;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha384};

    const NONCE: &str = "1234567890";
    const PUBLIC_KEY: &str = "hduabci29e0asdadans0212nsj0e3n";

    fn sample_evidence() -> String {
        let pubkey = json!({
            "algorithm": "".to_string(),
            "pubkey-length": "".to_string(),
            "pubkey": PUBLIC_KEY.to_string()
        })
        .to_string();
        let mut hasher = Sha384::new();
        hasher.update(NONCE);
        hasher.update(&pubkey);
        let hash = hasher.finalize();
        let tee_evidence = json!({
            "is_debuggable": false,
            "cpusvn": 1,
            "svn": 1,
            "report_data": base64::encode(hash)
        })
        .to_string();
        json!({
            "nonce": NONCE.to_owned(),
            "tee": "sample".to_string(),
            "tee-pubkey": pubkey,
            "tee-evidence": tee_evidence
        })
        .to_string()
    }

    fn sample_input(ver: u64) -> String {
        json!({
            "cpusvn": ver,
            "svn": ver
        })
        .to_string()
    }

    fn sample_reference(ver: u64) -> String {
        json!({
            "reference": {
                "cpusvn": ver,
                "svn": ver
            }
        })
        .to_string()
    }

    fn sample_policy() -> String {
        let policy = r#"
package policy
# Note: The testing policy
# By default, deny requests.
default allow = false
allow {
    input.cpusvn >= data.cpusvn
    input.svn >= data.svn
}
"#;
        policy.to_string()
    }

    async fn attestation() -> Result<(), String> {
        let service = Service::new();

        let evidence = sample_evidence();
        let res = service
            .attestation(&evidence, None, Some(sample_reference(1)))
            .await;
        assert!(res.is_ok(), "attestation should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert_eq!(v["allow"], json!(true));

        let res = service
            .attestation(&evidence, None, Some(sample_reference(5)))
            .await;
        assert!(res.is_ok(), "attestation should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert_eq!(v["allow"], json!(false));
        Ok(())
    }

    #[tokio::test]
    async fn test_attestation() {
        let res = attestation().await;
        assert!(res.is_ok(), "attestation() should success");
    }

    #[tokio::test]
    async fn test_attestation_spawn() {
        tokio::spawn(async {
            let res = attestation().await;
            assert!(res.is_ok(), "spawn attestation() should success");
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_default_policy() {
        let service = Service::new();
        let value = service.default_policy().await;
        assert!(value.is_ok(), "get opa's policy should success");
        assert!(
            value.unwrap() == std::include_str!("../default_policy.rego"),
            "policy should equal"
        );
    }

    #[tokio::test]
    async fn test_opa_test() {
        let service = Service::new();
        let res = service.opa_test(sample_policy(), sample_reference(1), sample_input(1));
        assert!(res.is_ok(), "opa test should success");
    }
}
