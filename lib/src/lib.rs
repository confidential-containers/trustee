use anyhow::{anyhow, Result};
use std::str::FromStr;

#[macro_use]
extern crate log;

extern crate strum;
#[macro_use]
extern crate strum_macros;

mod core;
use crate::core::verifier::policy::opa;

/// The supported TEE types:
/// - TDX: TDX TEE.
/// - SGX: SGX TEE.
/// - SEVSNP: SEV-SNP TEE.
/// - SAMPLE: A dummy TEE that used to test/demo the attestation service functionalities.
#[derive(Debug, EnumString)]
#[strum(ascii_case_insensitive)]
pub enum TEE {
    TDX,
    SGX,
    SEVSNP,
    SAMPLE,
}

#[derive(Debug)]
pub struct Service {
    pub attestation: core::Attestation,
}

impl Service {
    /// Create a new attestation service's instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use attestation_service::Service;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let service = Service::new();
    ///     assert!(service.is_ok());
    /// }
    /// ```
    pub fn new() -> Result<Self> {
        Ok(Self {
            attestation: core::Attestation::default(),
        })
    }

    /// Attest the received Evidence by the attestation service instance.
    ///
    /// # Examples
    ///
    /// ```
    /// use attestation_service::Service;
    /// use serde_json::json;
    /// use sha2::{Sha384, Digest};
    /// use base64;
    ///
    /// // sample TEE's evidence
    /// fn evidence() -> String {
    ///     let nonce = "the nonce".to_string();
    ///     let public_key = "the public key".to_string();
    ///     let pubkey = json!({
    ///         "algorithm": "".to_string(),
    ///         "pubkey-length": "".to_string(),
    ///         "pubkey": public_key
    ///     }).to_string();
    ///     let mut hasher = Sha384::new();
    ///     hasher.update(&nonce);
    ///     hasher.update(&pubkey);
    ///     let hash = hasher.finalize();
    ///     let tee_evidence = json!({
    ///         "is_debuggable": false,
    ///         "cpusvn": 1,
    ///         "svn": 1,
    ///         "report_data": base64::encode(hash)
    ///     }).to_string();
    ///     json!({
    ///         "nonce": nonce,
    ///         "tee": "sample".to_string(),
    ///         "tee-pubkey": pubkey,
    ///         "tee-evidence": tee_evidence
    ///     }).to_string()
    /// }
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let service = Service::new().unwrap();
    ///
    ///     // Attest the evidence with default OPA policy and reference data.
    ///     let res = service.attestation(&evidence(), None, None).await;
    ///     assert!(res.is_ok());
    ///
    ///     let policy = r#"
    /// package policy
    /// default allow = false
    ///
    /// allow {
    ///     input.cpusvn >= data.cpusvn
    ///     input.svn >= data.svn
    /// }
    /// "#.to_string();
    ///
    ///     let reference_data = json!({
    ///        "cpusvn": 1,
    ///        "svn": 1
    ///     }).to_string();
    ///
    ///     // Attest the evidence with customized OPA policy and reference data.
    ///     let res = service.attestation(&evidence(), Some(policy), Some(reference_data)).await;
    ///     assert!(res.is_ok());
    /// }
    /// ```
    pub async fn attestation(
        &self,
        evidence: &String,
        policy: Option<String>,
        reference_data: Option<String>,
    ) -> Result<String> {
        self.attestation
            .evaluate(evidence, policy, reference_data)
            .await
    }

    /// Get the specific TEE's Open Policy Agent default policy file.
    ///
    /// # Examples
    ///
    /// ```
    /// use attestation_service::{Service, TEE};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let service = Service::new().unwrap();
    ///     let res = service.default_policy(
    ///             TEE::SAMPLE,
    ///         )
    ///         .await;
    ///     assert!(res.is_ok());
    /// }
    /// ```
    pub async fn default_policy(&self, tee: TEE) -> Result<String> {
        self.attestation.policy(tee)
    }

    /// Get the specific TEE's Open Policy Agent default reference data file.
    ///
    /// # Examples
    ///
    /// ```
    /// use attestation_service::{Service, TEE};
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let service = Service::new().unwrap();
    ///     let res = service.default_reference_data(
    ///             TEE::SAMPLE,
    ///         )
    ///         .await;
    ///     assert!(res.is_ok());
    /// }
    /// ```
    pub async fn default_reference_data(&self, tee: TEE) -> Result<String> {
        self.attestation.reference_data(tee)
    }

    /// Evaluate the input data, policy file, and reference data by the OPA policy engine.
    ///
    /// # Examples
    ///
    /// ```
    /// use attestation_service::Service;
    /// use serde_json::json;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let service = Service::new().unwrap();
    ///     let policy = r#"
    /// package policy
    /// default allow = false
    ///
    /// allow {
    ///     input.cpusvn >= data.cpusvn
    ///     input.svn >= data.svn
    /// }
    /// "#.to_string();
    ///     let reference = json!({
    ///         "cpusvn": 1,
    ///         "svn": 1
    ///     }).to_string();
    ///     let input = json!({
    ///         "cpusvn": 2,
    ///         "svn": 2
    ///     }).to_string();
    ///     let res = service.opa_test(policy, reference, input);
    ///     assert!(res.is_ok());
    /// }
    /// ```
    pub fn opa_test(
        &self,
        policy_content: String,
        reference_content: String,
        input_content: String,
    ) -> Result<String> {
        opa::evaluate(policy_content, reference_content, input_content)
    }
}

#[cfg(test)]
mod tests {
    use super::{Service, TEE};
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
            "cpusvn": ver,
            "svn": ver
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
        let service = Service::new().unwrap();

        let evidence = sample_evidence();
        let res = service.attestation(&evidence, None, None).await;
        assert!(res.is_ok(), "attestation should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert!(v["result"] == "true".to_string(), "result should true");
        let policy_info: Value = serde_json::from_str(v["policy_info"].as_str().unwrap()).unwrap();
        assert!(
            policy_info["policy_name"] == "policy.rego".to_string(),
            "policy name should be policy.rego"
        );

        let res = service
            .attestation(&evidence, None, Some(sample_reference(5)))
            .await;
        assert!(res.is_ok(), "attestation should success");
        let v: Value = serde_json::from_str(&res.unwrap()).unwrap();
        assert!(v["result"] == "false".to_string(), "result should false");
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
        let service = Service::new().unwrap();
        let value = service.default_policy(TEE::SAMPLE).await;
        assert!(value.is_ok(), "get opa's policy should success");
        assert!(
            value.unwrap() == std::include_str!("./core/verifier/sample/policy.rego"),
            "policy should equal"
        );
    }

    #[tokio::test]
    async fn test_default_reference_data() {
        let service = Service::new().unwrap();
        let value = service.default_reference_data(TEE::SAMPLE).await;
        assert!(value.is_ok(), "get opa's reference data should success");
        assert!(
            value.unwrap() == std::include_str!("./core/verifier/sample/reference_data.json"),
            "reference data should equal"
        );
    }

    #[tokio::test]
    async fn test_opa_test() {
        let service = Service::new().unwrap();
        let res = service.opa_test(sample_policy(), sample_reference(1), sample_input(1));
        assert!(res.is_ok(), "opa test should success");
    }
}
