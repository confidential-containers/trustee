// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Context, Error, Result, anyhow, bail};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use ear::{Algorithm, Appraisal, Ear, Extensions, RawValue, RawValueKind, VerifierID};
use jsonwebtoken::jwk::{self, JwkSet};
use key_value_storage::KeyValueStorageInstance;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use policy_engine::rego::RegorusExtension;
use policy_engine::{PolicyEngine, rego::Regorus};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{debug, info, warn};

use crate::ear_token::EarTokenConfiguration;
use crate::ear_token::policy::PolicyDeclaration;
use crate::rvps::RvpsClient;
use crate::{
    TeeClaims,
    ear_token::claims::{
        TransformedClaims, appraisal_attester_claims, appraisal_verifier_claims, policy_input_json,
    },
};

/// The policy claim that will hold trust claims.
pub const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";
/// The policy claim that will hold extensions.
pub const EXTENSIONS_RULE: &str = "data.policy.extensions";

/// Id of the built-in policy that judges CPU TEE results.
pub const DEFAULT_CPU_POLICY_ID: &str = "default_cpu";
/// Id of the built-in policy that judges GPU results.
pub const DEFAULT_GPU_POLICY_ID: &str = "default_gpu";
/// Id of the built-in policy that judges NVSwitch results.
pub const DEFAULT_SWITCH_POLICY_ID: &str = "default_switch";
/// Id of the built-in policy that judges the PPCIE topology result.
pub const DEFAULT_PPCIE_POLICY_ID: &str = "default_ppcie";

/// Decode a hex string into bytes.
fn hex_param(value: &regorus::Value) -> Result<Vec<u8>> {
    Ok(hex::decode(value.as_string()?.as_ref())?)
}

/// Build the `sha256_extend` policy extension.
///
/// It takes two hex-encoded strings, `old` and `digest`, and returns the hex-encoded
/// SHA-256 of their concatenation, like a TPM PCR extend.
fn sha256_extend_extension() -> RegorusExtension {
    RegorusExtension {
        name: "sha256_extend".to_string(),
        id: 2,
        extension: Box::new(|params: Vec<regorus::Value>| {
            if params.len() != 2 {
                bail!("sha256_extend extension requires exactly two parameters");
            }
            let old = hex_param(&params[0])
                .context("sha256_extend extension parameter `old` must be a hex string")?;
            let digest = hex_param(&params[1])
                .context("sha256_extend extension parameter `digest` must be a hex string")?;
            let extended = Sha256::new().chain_update(old).chain_update(digest);
            Ok(regorus::Value::from(hex::encode(extended.finalize())))
        }),
    }
}

pub struct EarAttestationTokenBroker {
    config: EarTokenConfiguration,
    private_key: EcKey<Private>,
    cert_url: Option<String>,
    cert_chain: Option<Vec<X509>>,
    policy_engine: PolicyEngine<Regorus>,
}

impl EarAttestationTokenBroker {
    pub async fn new(
        config: EarTokenConfiguration,
        storage: KeyValueStorageInstance,
    ) -> Result<Self> {
        let policy_engine = PolicyEngine::<Regorus>::new(storage);

        let default_cpu_policy = include_str!("ear_default_policy_cpu.rego");

        policy_engine
            .set_policy(DEFAULT_CPU_POLICY_ID, default_cpu_policy, false)
            .await?;

        let default_gpu_policy = include_str!("ear_default_policy_gpu.rego");

        policy_engine
            .set_policy(DEFAULT_GPU_POLICY_ID, default_gpu_policy, false)
            .await?;

        let default_switch_policy = include_str!("ear_default_policy_switch.rego");

        policy_engine
            .set_policy(DEFAULT_SWITCH_POLICY_ID, default_switch_policy, false)
            .await?;

        let default_ppcie_policy = include_str!("ear_default_policy_ppcie.rego");

        policy_engine
            .set_policy(DEFAULT_PPCIE_POLICY_ID, default_ppcie_policy, false)
            .await?;

        if config.signer.is_none() {
            info!(
                "No Token Signer key in config file, create an ephemeral key and without CA pubkey cert"
            );
            return Ok(Self {
                private_key: generate_ec_keys()?.0,
                config,
                cert_url: None,
                cert_chain: None,
                policy_engine,
            });
        }

        let signer = config.signer.clone().unwrap();
        let pem_data = std::fs::read(&signer.key_path)
            .map_err(|e| anyhow!("Read Token Signer private key failed: {:?}", e))?;
        let private_key = EcKey::private_key_from_pem(&pem_data)?;
        if private_key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
            bail!("Only P-256 attestation token signing keys are supported");
        }

        let cert_chain = signer
            .cert_path
            .as_ref()
            .map(|cert_path| -> Result<Vec<X509>> {
                let pem_cert_chain = std::fs::read_to_string(cert_path)
                    .map_err(|e| anyhow!("Read Token Signer cert file failed: {:?}", e))?;
                X509::stack_from_pem(pem_cert_chain.as_bytes())
                    .map_err(|_| anyhow!("Invalid PEM certificate chain"))
            })
            .transpose()?;

        Ok(Self {
            config,
            private_key,
            cert_url: signer.cert_url,
            cert_chain,
            policy_engine,
        })
    }
}

/// Extensions that will be added to the attestation token.
#[derive(Debug, Deserialize)]
pub struct TokenExtension {
    pub name: String,
    pub key: i32,
    pub value: Value,
}

#[derive(Debug)]
pub struct EvaluationResult {
    pub trust_claims: Value,
    /// Extensions to be added to the attestation token.
    pub extensions: Vec<TokenExtension>,
    pub policy_hash: String,
}

impl EarAttestationTokenBroker {
    /// Issue an EAR for the given verifier results.
    ///
    /// Every policy in `policy_ids` is used as is: no suffix is appended and
    /// no group is expanded. A policy judges all results whose device name it
    /// declares in `devices`, together as one input, and produces one
    /// submodule named by the `submod` it declares. The id of the policy is
    /// recorded in that submodule.
    ///
    /// - Two policies that declare the same `submod` are a configuration error.
    /// - A policy that accepts none of the results does not run and produces
    ///   no submodule.
    /// - A result that no policy accepts is not appraised, the token has no
    ///   statement about it.
    pub async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        rvps_client: Option<RvpsClient>,
    ) -> Result<String> {
        if policy_ids.is_empty() {
            bail!("No policy is given for EAR token generation.");
        }

        let policies = self.load_policies(policy_ids).await?;

        let mut device_claims_map: BTreeMap<String, Vec<TransformedClaims>> = BTreeMap::new();
        for tee_claims in all_tee_claims {
            let device = tee_claims.device.clone();
            let claim = TransformedClaims::new(
                tee_claims.claims,
                tee_claims.init_data_claims,
                tee_claims.runtime_data_claims,
                tee_claims.tee,
                tee_claims.device,
                self.config.verbose_token,
            )?;
            device_claims_map.entry(device).or_default().push(claim);
        }

        let mut submods = BTreeMap::new();
        let mut device_evaluated = device_claims_map
            .keys()
            .map(|device| (device.to_string(), false))
            .collect::<BTreeMap<_, _>>();

        for declaration in &policies {
            let accepted: Vec<&str> = device_claims_map
                .keys()
                .filter(|device| declaration.accepts(device))
                .map(|device| device.as_str())
                .collect();

            if accepted.is_empty() {
                debug!(
                    policy = declaration.policy_id,
                    "No verifier result is accepted by the policy, skip it."
                );
                continue;
            }

            let accepted_devices: Vec<&TransformedClaims> = accepted
                .iter()
                .flat_map(|i| device_claims_map[*i].iter())
                .collect();
            let appraisal = self
                .appraise(declaration, &accepted_devices, rvps_client.clone())
                .await?;

            for i in accepted {
                let _ = device_evaluated.insert(i.to_string(), true);
            }
            submods.insert(declaration.submod.clone(), appraisal);
        }

        for (device, _) in device_evaluated.iter().filter(|(_, done)| !*done) {
            warn!(
                device = device,
                "No policy accepts the verifier result of the device, it is not part of the token."
            );
        }

        if submods.is_empty() {
            bail!("None of the policies accepts any of the verifier results.");
        }

        let now = OffsetDateTime::now_utc();
        let iat = now.unix_timestamp();
        let exp = now
            .checked_add(TimeDuration::minutes(self.config.duration_min))
            .ok_or(anyhow!("Token expiration overflow."))?
            .unix_timestamp();

        let mut extensions = Extensions::new();
        extensions.register("iss", 1, RawValueKind::String)?;
        extensions.set_by_name("iss", RawValue::String(self.config.issuer_name.clone()))?;

        let mut ear = Ear {
            profile: self.config.profile_name.clone(),
            iat,
            vid: VerifierID {
                build: self.config.build_name.clone(),
                developer: self.config.developer_name.clone(),
            },
            raw_evidence: None,
            nonce: None,
            submods,
            extensions,
            exp: Some(exp),
            status: None,
            topology: None,
        };

        ear.status = Some(ear.most_severe_submod_status());

        debug!(ear =? ear, "Unsigned EAR Token");

        let mut jwt_header = ear::new_jwt_header(&Algorithm::ES256)?;
        jwt_header.jwk = Some(self.pubkey_jwk()?);

        let pkey = PKey::from_ec_key(self.private_key.clone())?;
        let private_key_bytes = pkey.private_key_to_pem_pkcs8()?;

        let signed_ear = ear.sign_jwt_pem_with_header(&jwt_header, &private_key_bytes)?;

        Ok(signed_ear)
    }

    /// Store a policy. A policy that does not declare `devices` and `submod`
    /// is rejected, it could never be used.
    pub async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
        let _ = PolicyDeclaration::from_raw_policy_text(&policy_id, &policy)
            .with_context(|| format!("Policy {policy_id} is not accepted"))?;
        self.policy_engine
            .set_policy(&policy_id, &policy, true)
            .await
            .map_err(Error::from)
    }

    pub async fn list_policies(&self) -> Result<Vec<String>> {
        self.policy_engine
            .list_policies()
            .await
            .map_err(Error::from)
    }

    pub async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.policy_engine
            .get_policy(&policy_id)
            .await
            .map_err(Error::from)
    }

    pub fn get_jwks(&self) -> Result<JwkSet> {
        Ok(JwkSet {
            keys: vec![self.pubkey_jwk()?],
        })
    }
}

impl EarAttestationTokenBroker {
    /// Read the given policies and their declarations, do the following check
    /// 1. Deduplicate input policy ids
    /// 2. Read the policies and their declarations. If any two policies declare
    ///    the same submod, it is a configuration error.
    async fn load_policies(&self, policy_ids: Vec<String>) -> Result<Vec<PolicyDeclaration>> {
        let mut policies = Vec::new();
        // deduplicate policy ids
        let policy_ids = policy_ids.into_iter().collect::<BTreeSet<_>>();
        let mut submods = BTreeMap::new();
        for policy_id in policy_ids {
            let text = self.policy_engine.get_policy(&policy_id).await?;
            let declaration = PolicyDeclaration::from_raw_policy_text(&policy_id, &text)?;
            if let Some(other) = submods.get(&declaration.submod) {
                bail!(
                    "Policies {} and {} both declare the submod `{}`",
                    other,
                    declaration.policy_id,
                    declaration.submod,
                );
            }
            submods.insert(declaration.submod.clone(), declaration.policy_id.clone());
            policies.push(declaration);
        }

        Ok(policies)
    }

    /// Evaluate the policy on all of `devices` together and make an appraisal
    /// of the result.
    async fn appraise(
        &self,
        declaration: &PolicyDeclaration,
        devices: &[&TransformedClaims],
        rvps_client: Option<RvpsClient>,
    ) -> Result<Appraisal> {
        let policy_id = &declaration.policy_id;
        let mut appraisal = Appraisal::new();

        // Add rego extensions
        let mut extensions = vec![sha256_extend_extension()];
        if let Some(rvps_client) = rvps_client {
            extensions.push(query_reference_value_extension(rvps_client));
        }

        let policy_results = self
            .policy_engine
            .engine
            .evaluate(
                None,
                policy_input_json(devices)?,
                declaration.text.clone(),
                vec![TRUST_CLAIMS_RULE.to_string(), EXTENSIONS_RULE.to_string()],
                extensions,
            )
            .await?;

        match policy_results
            .eval_rules_result
            .get(TRUST_CLAIMS_RULE)
            .with_context(|| {
                format!("Trust claims rule {TRUST_CLAIMS_RULE} not found for policy {policy_id}")
            })? {
            Some(value) => {
                let trust_claims = value.as_object().context("Trust claims is not an object")?;
                for (k, v) in trust_claims {
                    let claim_value = v.as_i64().context("Trust claim value not number")?;
                    debug!(policy_id = policy_id, "Trust claim: {}: {}", k, claim_value);

                    appraisal
                        .trust_vector
                        .mut_by_name(k)
                        .with_context(|| {
                            format!("Policy {policy_id} sets the unknown trust claim `{k}`")
                        })?
                        .set(claim_value as i8);
                }
            }
            None => {
                warn!(
                    "No trust claims found by enforcing policy {policy_id}, set all TrustVector claims to 0"
                );
                appraisal.trust_vector.set_all(0);
            }
        }

        if !appraisal.trust_vector.any_set() {
            bail!("At least one policy claim must be set.");
        }

        // Set extensions from policy result
        let mut extensions = Extensions::new();
        let extension_claims = policy_results
            .eval_rules_result
            .get(EXTENSIONS_RULE)
            .context("Extensions rule not found")?
            .as_ref()
            .cloned()
            .unwrap_or(json!([]));

        let extension_claims = serde_json::from_value::<Vec<TokenExtension>>(extension_claims)?;
        for extension in extension_claims {
            let extension_value: RawValue =
                serde_json::from_str(&serde_json::to_string(&extension.value)?)?;

            extensions.register(&extension.name, extension.key, extension_value.kind())?;
            extensions.set_by_name(&extension.name, extension_value)?;
        }

        appraisal.extensions = extensions;

        appraisal.attester_claims = appraisal_attester_claims(devices)?;
        appraisal.verifier_claims = appraisal_verifier_claims(devices)?;
        appraisal.policy_ids = vec![policy_id.to_string()];
        appraisal.update_status_from_trust_vector();

        Ok(appraisal)
    }
}

/// Build the `query_reference_value` policy extension.
///
/// It takes the id of a reference value and returns the value known to RVPS,
/// or null if RVPS does not know the id.
fn query_reference_value_extension(rvps_client: RvpsClient) -> RegorusExtension {
    RegorusExtension {
        name: "query_reference_value".to_string(),
        id: 1,
        extension: Box::new(move |params: Vec<regorus::Value>| {
            if params.len() != 1 {
                bail!("query_reference_value extension requires exactly one parameter");
            }
            let id = params[0]
                .as_string()
                .context("query_reference_value extension parameter must be a string")?
                .to_string();
            debug!("query reference value from RVPS: {id}");
            let rvps_client = rvps_client.clone();
            let reference_value_id = params[0].as_string()?.to_string();
            // Policy evaluation runs on tokio's blocking pool, so it is
            // safe to block_on the RVPS query here without starving
            // runtime workers that drive the gRPC connection pool.
            let result = tokio::runtime::Handle::current()
                .block_on(async move {
                    tokio::time::timeout(Duration::from_secs(10), async {
                        rvps_client
                            .lock()
                            .await
                            .query_reference_value(&reference_value_id)
                            .await
                    })
                    .await
                    .map_err(|e| anyhow!("Get Reference Value from RVPS timeout: {e:?}"))?
                })
                .map_err(|e| anyhow!("Get Reference Value from RVPS failed: {e:?}"))?;

            match result {
                Some(v) => {
                    let json_value = serde_json::to_value(v)?;
                    let value: regorus::Value = serde_json::from_value(json_value)?;
                    Ok(value)
                }
                None => {
                    warn!(
                        "No reference value found for the given id: {id}, use NULL as the returned value"
                    );
                    Ok(regorus::Value::Null)
                }
            }
        }),
    }
}

impl EarAttestationTokenBroker {
    fn pubkey_jwk(&self) -> Result<jwk::Jwk> {
        let chain = self
            .cert_chain
            .as_ref()
            .map(|certs| -> Result<Vec<String>> {
                let mut chain = vec![];
                for cert in certs {
                    let der = cert.to_der()?;
                    chain.push(STANDARD.encode(der));
                }
                Ok(chain)
            })
            .transpose()?;

        let common = jwk::CommonParameters {
            key_algorithm: Some(jwk::KeyAlgorithm::ES256),
            x509_url: self.cert_url.clone(),
            x509_chain: chain,
            ..Default::default()
        };

        let public_key = self.private_key.public_key();
        let group = self.private_key.group();

        let mut ctx = BigNumContext::new()?;
        let mut x = BigNum::new()?;
        let mut y = BigNum::new()?;
        public_key.affine_coordinates_gfp(group, &mut x, &mut y, &mut ctx)?;

        // RFC 7518 requires fixed-length coordinate octet strings (32 bytes for P-256).
        let field_size = group.degree().div_ceil(8);

        let algorithm = jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
            key_type: jwk::EllipticCurveKeyType::EC,
            curve: jwk::EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x.to_vec_padded(field_size as i32)?),
            y: URL_SAFE_NO_PAD.encode(y.to_vec_padded(field_size as i32)?),
        });

        let jwk = jwk::Jwk { common, algorithm };

        Ok(jwk)
    }
}

fn generate_ec_keys() -> Result<(EcKey<Private>, Vec<u8>, Vec<u8>)> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key.clone())?;

    Ok((
        ec_key,
        pkey.private_key_to_pem_pkcs8()?,
        pkey.public_key_to_pem()?,
    ))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::DecodingKey;
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
    use kbs_types::Tee;
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType, SetParameters};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::{AS_POLICY_STORAGE_NAMESPACE, TeeClaims, ear_token::TokenSignerConfig};

    use super::*;

    fn eval_sha256_extend(policy: &str, input: &str) -> regorus::Value {
        let mut engine = regorus::Engine::new();
        let ext = sha256_extend_extension();
        engine
            .add_extension(ext.name, ext.id, ext.extension)
            .unwrap();
        engine
            .add_policy("".to_string(), policy.to_string())
            .unwrap();
        engine.set_input_json(input).unwrap();
        engine.eval_rule("data.policy.out".to_string()).unwrap()
    }

    /// The result is the SHA-256 of the concatenated bytes: "a" || "bc" is "abc".
    #[test]
    fn test_sha256_extend_extension() {
        let out = eval_sha256_extend(
            "package policy\nout := sha256_extend(hex.encode(\"a\"), hex.encode(\"bc\"))",
            "{}",
        );
        assert_eq!(
            out.as_string().unwrap().as_ref(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// PCR[8] = SHA256(pcr8_base || SHA256(init-data)), with an arbitrary non-zero base.
    #[test]
    fn test_sha256_extend_extension_pcr8() {
        let out = eval_sha256_extend(
            "package policy\nout := sha256_extend(input.base, input.init_data_digest)",
            &json!({
                // Bytes 0x00..0x1f.
                "base": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                // SHA256("init-data")
                "init_data_digest": "d61c6a7f2f8d5bdb3b2d573e434c2b15c8a4babd11bb288b08be3534566ba3ee",
            })
            .to_string(),
        );
        assert_eq!(
            out.as_string().unwrap().as_ref(),
            "2b08e35daa2aee3d0d3f1bfdae7a43251faedaf43e2d488db2a068fb66d2c461"
        );
    }

    #[test]
    fn test_sha256_extend_extension_rejects_bad_params() {
        let mut extend = sha256_extend_extension().extension;
        assert!(extend(vec![regorus::Value::from("00"), regorus::Value::from("zz")]).is_err());
        assert!(extend(vec![regorus::Value::from("00")]).is_err());
    }

    #[tokio::test]
    async fn test_issue_ear_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = EarTokenConfiguration::default();

        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy.rego"),
                SetParameters {
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let _token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    device: "sample".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["ear_no_rv_policy".into()],
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_issue_and_validate_ear() {
        let (_pkey, private_key_bytes, public_key_bytes) = generate_ec_keys().unwrap();
        let mut private_key_file = NamedTempFile::new().unwrap();
        private_key_file.write_all(&private_key_bytes).unwrap();

        let signer = TokenSignerConfig {
            key_path: private_key_file.path().to_str().unwrap().to_string(),
            cert_url: None,
            cert_path: None,
        };

        let config = EarTokenConfiguration {
            signer: Some(signer),
            ..Default::default()
        };
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy.rego"),
                SetParameters {
                    overwrite: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();
        let token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    device: "sample".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["ear_no_rv_policy".into()],
                None,
            )
            .await
            .unwrap();

        let public_key = DecodingKey::from_ec_pem(&public_key_bytes).unwrap();

        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
    }

    async fn broker_with_policies(policies: &[(&str, String)]) -> EarAttestationTokenBroker {
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        for (id, policy) in policies {
            storage
                .set(
                    &format!("{id}.rego"),
                    policy.as_bytes(),
                    SetParameters {
                        overwrite: true,
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
        }
        EarAttestationTokenBroker::new(EarTokenConfiguration::default(), storage)
            .await
            .unwrap()
    }

    /// A policy that judges `devices` and grants `hardware` 2 iff it is
    /// given exactly `expected_count` results.
    fn counting_policy(devices: &[&str], submod: &str, expected_count: usize) -> String {
        format!(
            r#"
package policy
import rego.v1

devices := {devices}
submod := "{submod}"

default hardware := 97
hardware := 2 if {{ count(input.devices) == {expected_count} }}

trust_claims := {{"hardware": hardware}}
"#,
            devices = json!(devices),
        )
    }

    fn device_claims(tee: Tee, device: &str, claims: Value) -> TeeClaims {
        TeeClaims {
            tee,
            device: device.to_string(),
            claims,
            runtime_data_claims: json!({"runtime_data": "111"}),
            init_data_claims: json!({"initdata": "111"}),
        }
    }

    /// The payload of a token. The signature is not checked here.
    fn token_payload(token: &str) -> Value {
        let payload = token.split('.').nth(1).unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    }

    fn submod_names(token: &str) -> Vec<String> {
        token_payload(token)["submods"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    #[tokio::test]
    async fn test_builtin_policies_declare_their_devices() {
        let broker = broker_with_policies(&[]).await;
        let declarations = broker
            .load_policies(
                crate::ear_token::DEFAULT_POLICY_IDS
                    .map(String::from)
                    .to_vec(),
            )
            .await
            .unwrap();

        let by_id = |id: &str| declarations.iter().find(|p| p.policy_id == id).unwrap();
        assert!(by_id("default_cpu").accepts("tdx"));
        assert!(by_id("default_cpu").accepts("snp"));
        assert!(!by_id("default_cpu").accepts("nvidia-gpu"));
        assert!(by_id("default_gpu").accepts("nvidia-gpu"));
        assert!(by_id("default_switch").accepts("nvidia-switch"));
        assert!(by_id("default_ppcie").accepts("nvidia-ppcie"));

        // The built-in policies keep the names of the token entries.
        assert_eq!(by_id("default_cpu").submod, "cpu0");
        assert_eq!(by_id("default_gpu").submod, "gpu0");
        assert_eq!(by_id("default_switch").submod, "switch0");
        assert_eq!(by_id("default_ppcie").submod, "ppcie0");
    }

    #[tokio::test]
    async fn test_policy_id_is_recorded_as_is() {
        let broker =
            broker_with_policies(&[("acme", counting_policy(&["sample"], "cpu0", 1))]).await;

        let token = broker
            .issue(
                vec![device_claims(Tee::Sample, "sample", json!({}))],
                vec!["acme".into()],
                None,
            )
            .await
            .unwrap();

        let payload = token_payload(&token);
        assert_eq!(
            payload["submods"]["cpu0"]["ear_appraisal_policy_ids"],
            json!(["acme"])
        );
        assert_eq!(
            payload["submods"]["cpu0"]["ear_trustworthiness_vector"]["hardware"],
            2
        );
    }

    #[tokio::test]
    async fn test_one_result_is_judged_by_every_policy_that_accepts_it() {
        let broker = broker_with_policies(&[
            ("hardware", counting_policy(&["tdx", "snp"], "cpu", 1)),
            ("runtime", counting_policy(&["tdx", "vtpm"], "rtmr", 1)),
        ])
        .await;

        // A TDX result matches both policies.
        let token = broker
            .issue(
                vec![device_claims(Tee::Tdx, "tdx", json!({}))],
                vec!["hardware".into(), "runtime".into()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(submod_names(&token), ["cpu", "rtmr"]);
        let payload = token_payload(&token);
        assert_eq!(
            payload["submods"]["cpu"]["ear_appraisal_policy_ids"],
            json!(["hardware"])
        );
        assert_eq!(
            payload["submods"]["rtmr"]["ear_appraisal_policy_ids"],
            json!(["runtime"])
        );

        // An SNP result only matches `hardware`, `runtime` does not accept it
        // and there is no `rtmr` entry.
        let token = broker
            .issue(
                vec![device_claims(Tee::Snp, "snp", json!({}))],
                vec!["hardware".into(), "runtime".into()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(submod_names(&token), ["cpu"]);
        assert!(token_payload(&token)["submods"].get("rtmr").is_none());

        // If `runtime` is the only policy, nothing accepts the SNP result.
        let err = broker
            .issue(
                vec![device_claims(Tee::Snp, "snp", json!({}))],
                vec!["runtime".into()],
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("None of the policies"), "{err}");
    }

    #[tokio::test]
    async fn test_policy_judges_all_accepted_results_together() {
        let broker =
            broker_with_policies(&[("node", counting_policy(&["tdx", "tpm"], "node", 2))]).await;

        let results = |with_tpm: bool| {
            let mut results = vec![device_claims(
                Tee::Tdx,
                "tdx",
                json!({"a": 1, "report_data": "00"}),
            )];
            if with_tpm {
                results.push(device_claims(
                    Tee::Tpm,
                    "tpm",
                    json!({"b": 2, "report_data": "01"}),
                ));
            }
            // A result of another device is not passed to the policy.
            results.push(device_claims(Tee::Sample, "sample", json!({})));
            results
        };

        let token = broker
            .issue(results(true), vec!["node".into()], None)
            .await
            .unwrap();
        let payload = token_payload(&token);
        assert_eq!(submod_names(&token), ["node"]);
        assert_eq!(
            payload["submods"]["node"]["ear_trustworthiness_vector"]["hardware"],
            2
        );
        // The claims of all accepted devices are reported by device name, none is picked.
        let attester = payload["submods"]["node"]["ear_attester_claims"]
            .as_object()
            .unwrap();
        assert_eq!(attester.keys().collect::<Vec<_>>(), ["tdx", "tpm"]);
        assert_eq!(attester["tdx"][0]["tee"], "tdx");
        assert_eq!(attester["tdx"][0]["claims"], json!({"a": 1}));
        assert_eq!(attester["tpm"][0]["claims"], json!({"b": 2}));
        // The data of the request is reported once, KBS reads the key of the
        // guest from here.
        assert_eq!(
            payload["submods"]["node"]["ear_verifier_claims"],
            json!({"runtime_data": {"runtime_data": "111"}, "devices": ["tdx", "tpm"]})
        );

        // One device less and the policy is no longer satisfied.
        let token = broker
            .issue(results(false), vec!["node".into()], None)
            .await
            .unwrap();
        assert_eq!(
            token_payload(&token)["submods"]["node"]["ear_trustworthiness_vector"]["hardware"],
            97
        );
    }

    /// The GPUs of a node share a name. All of them are passed to the policy,
    /// and each of them is reported in the token.
    #[tokio::test]
    async fn test_results_with_the_same_device_name_are_all_judged() {
        let broker =
            broker_with_policies(&[("gpu", counting_policy(&["nvidia-gpu"], "gpu", 2))]).await;

        let token = broker
            .issue(
                vec![
                    device_claims(Tee::Nvidia, "nvidia-gpu", json!({"gpu": 0})),
                    device_claims(Tee::Nvidia, "nvidia-gpu", json!({"gpu": 1})),
                ],
                vec!["gpu".into()],
                None,
            )
            .await
            .unwrap();
        let appraisal = &token_payload(&token)["submods"]["gpu"];
        assert_eq!(appraisal["ear_trustworthiness_vector"]["hardware"], 2);

        let attester = &appraisal["ear_attester_claims"]["nvidia-gpu"];
        assert_eq!(attester.as_array().unwrap().len(), 2);
        assert_eq!(attester[0]["claims"], json!({"gpu": 0}));
        assert_eq!(attester[1]["claims"], json!({"gpu": 1}));
        assert_eq!(
            appraisal["ear_verifier_claims"]["devices"],
            json!(["nvidia-gpu"])
        );
    }

    /// An untrusted GPU is never covered by a trusted one, whatever the order.
    #[tokio::test]
    async fn test_builtin_gpu_policy_judges_every_gpu() {
        let broker = broker_with_policies(&[]).await;
        let mut untrusted = trusted_gpu_claims();
        untrusted["x-nvidia-gpu-attestation-report-signature-verified"] = json!(false);

        let hardware = |gpus: Vec<Value>| {
            let broker = &broker;
            async move {
                let token = broker
                    .issue(
                        gpus.into_iter()
                            .map(|claims| device_claims(Tee::Nvidia, "nvidia-gpu", claims))
                            .collect(),
                        vec!["default_gpu".into()],
                        None,
                    )
                    .await
                    .unwrap();
                token_payload(&token)["submods"]["gpu0"]["ear_trustworthiness_vector"]["hardware"]
                    .as_i64()
                    .unwrap()
            }
        };

        assert_eq!(
            hardware(vec![trusted_gpu_claims(), trusted_gpu_claims()]).await,
            2
        );
        assert_eq!(
            hardware(vec![trusted_gpu_claims(), untrusted.clone()]).await,
            97
        );
        assert_eq!(hardware(vec![untrusted, trusted_gpu_claims()]).await, 97);
    }

    #[tokio::test]
    async fn test_policy_without_matching_result_does_not_run() {
        let broker = broker_with_policies(&[
            ("cpu", counting_policy(&["tdx"], "cpu", 1)),
            ("gpu", counting_policy(&["nvidia-gpu"], "gpu", 1)),
        ])
        .await;

        let token = broker
            .issue(
                vec![device_claims(Tee::Tdx, "tdx", json!({}))],
                vec!["cpu".into(), "gpu".into()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(submod_names(&token), ["cpu"]);
    }

    #[tokio::test]
    async fn test_issue_fails_if_no_policy_accepts_a_result() {
        let broker = broker_with_policies(&[("cpu", counting_policy(&["tdx"], "cpu", 1))]).await;

        let err = broker
            .issue(
                vec![device_claims(Tee::Sample, "sample", json!({}))],
                vec!["cpu".into()],
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("None of the policies"), "{err}");
    }

    #[tokio::test]
    async fn test_duplicate_submod_is_a_configuration_error() {
        let broker = broker_with_policies(&[
            ("a", counting_policy(&["tdx"], "same", 1)),
            ("b", counting_policy(&["snp"], "same", 1)),
        ])
        .await;

        // The error does not depend on the results of the attestation.
        let err = broker
            .issue(
                vec![device_claims(Tee::Tdx, "tdx", json!({}))],
                vec!["a".into(), "b".into()],
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains("both declare the submod"), "{err}");
    }

    #[tokio::test]
    async fn test_set_policy_rejects_policy_without_declaration() {
        let broker = broker_with_policies(&[]).await;

        for policy in [
            "package policy\ndefault hardware := 97",
            "package policy\ndevices := [\"tdx\"]",
            "package policy\ndevices := []\nsubmod := \"a\"",
            "this is not rego",
        ] {
            assert!(
                broker
                    .set_policy("bad".into(), policy.to_string())
                    .await
                    .is_err(),
                "{policy}"
            );
        }
        // Nothing was stored.
        assert!(broker.get_policy("bad".into()).await.is_err());

        broker
            .set_policy("good".into(), counting_policy(&["tdx"], "cpu", 1))
            .await
            .unwrap();
        assert!(broker.get_policy("good".into()).await.is_ok());
    }

    #[tokio::test]
    async fn test_replaced_policy_is_read_with_its_own_declaration() {
        let broker = broker_with_policies(&[]).await;
        let issue = |device: &'static str, tee: Tee| {
            let broker = &broker;
            async move {
                broker
                    .issue(
                        vec![device_claims(tee, device, json!({}))],
                        vec!["p".into()],
                        None,
                    )
                    .await
            }
        };

        broker
            .set_policy("p".into(), counting_policy(&["tdx"], "first", 1))
            .await
            .unwrap();
        assert_eq!(
            submod_names(&issue("tdx", Tee::Tdx).await.unwrap()),
            ["first"]
        );

        // The declaration of the first version must not be used for the replacement.
        broker
            .set_policy("p".into(), counting_policy(&["snp"], "second", 1))
            .await
            .unwrap();
        assert!(issue("tdx", Tee::Tdx).await.is_err());
        assert_eq!(
            submod_names(&issue("snp", Tee::Snp).await.unwrap()),
            ["second"]
        );

        // The same content under another id is recorded with its own id.
        broker
            .set_policy("q".into(), counting_policy(&["snp"], "second", 1))
            .await
            .unwrap();
        let token = broker
            .issue(
                vec![device_claims(Tee::Snp, "snp", json!({}))],
                vec!["q".into()],
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            token_payload(&token)["submods"]["second"]["ear_appraisal_policy_ids"],
            json!(["q"])
        );
    }

    #[tokio::test]
    async fn test_policy_given_twice_counts_once() {
        let broker = broker_with_policies(&[("cpu", counting_policy(&["tdx"], "cpu", 1))]).await;

        broker
            .issue(
                vec![device_claims(Tee::Tdx, "tdx", json!({}))],
                vec!["cpu".into(), "cpu".into()],
                None,
            )
            .await
            .unwrap();
    }

    #[rstest::rstest]
    #[case::no_devices(
        "package policy\nsubmod := \"a\"\ntrust_claims := {\"hardware\": 2}",
        "does not declare `devices`"
    )]
    #[case::no_submod(
        "package policy\ndevices := [\"tdx\"]\ntrust_claims := {\"hardware\": 2}",
        "does not declare `submod`"
    )]
    #[case::empty_devices("package policy\ndevices := []\nsubmod := \"a\"", "is empty")]
    #[case::bad_devices("package policy\ndevices := [1]\nsubmod := \"a\"", "non-empty strings")]
    #[case::empty_submod("package policy\ndevices := [\"tdx\"]\nsubmod := \"\"", "is empty")]
    #[case::bad_submod("package policy\ndevices := [\"tdx\"]\nsubmod := 1", "not a string")]
    #[tokio::test]
    async fn test_invalid_declaration_is_rejected(#[case] policy: &str, #[case] error: &str) {
        let broker = broker_with_policies(&[("bad", policy.to_string())]).await;

        let err = broker
            .issue(
                vec![device_claims(Tee::Tdx, "tdx", json!({}))],
                vec!["bad".into()],
                None,
            )
            .await
            .unwrap_err();
        assert!(err.to_string().contains(error), "{err}");
    }

    /// NVIDIA claims of a GPU that passed the hardware checks of the built-in policy.
    fn trusted_gpu_claims() -> Value {
        json!({
            "x-nvidia-gpu-attestation-report-cert-chain": {
                "x-nvidia-cert-ocsp-status": "good",
                "x-nvidia-cert-status": "valid",
            },
            "x-nvidia-gpu-attestation-report-cert-chain-fwid-match": true,
            "x-nvidia-gpu-attestation-report-parsed": true,
            "x-nvidia-gpu-attestation-report-signature-verified": true,
            "x-nvidia-gpu-arch-check": true,
        })
    }

    #[tokio::test]
    async fn test_builtin_gpu_policy_only_trusts_a_verified_gpu() {
        let broker = broker_with_policies(&[]).await;
        let hardware = |gpus: Vec<Value>| {
            let broker = &broker;
            async move {
                let token = broker
                    .issue(
                        gpus.into_iter()
                            .map(|claims| device_claims(Tee::Nvidia, "nvidia-gpu", claims))
                            .collect(),
                        vec!["default_gpu".into()],
                        None,
                    )
                    .await
                    .unwrap();
                token_payload(&token)["submods"]["gpu0"]["ear_trustworthiness_vector"]["hardware"]
                    .as_i64()
                    .unwrap()
            }
        };

        assert_eq!(hardware(vec![trusted_gpu_claims()]).await, 2);

        let mut untrusted = trusted_gpu_claims();
        untrusted["x-nvidia-gpu-attestation-report-signature-verified"] = json!(false);
        assert_eq!(hardware(vec![untrusted]).await, 97);
    }

    /// Evaluate `rule` of the built-in CPU policy, `query_reference_value`
    /// answers every query with `["good"]`.
    fn eval_default_cpu_policy(input: Value, rule: &str) -> regorus::Value {
        let mut engine = regorus::Engine::new();
        engine
            .add_extension(
                "query_reference_value".to_string(),
                1,
                Box::new(|_params: Vec<regorus::Value>| {
                    Ok(regorus::Value::from_json_str(r#"["good"]"#).unwrap())
                }),
            )
            .unwrap();
        engine
            .add_policy(
                "".to_string(),
                include_str!("ear_default_policy_cpu.rego").to_string(),
            )
            .unwrap();
        engine.set_input_json(&input.to_string()).unwrap();
        engine.eval_rule(rule.to_string()).unwrap()
    }

    #[test]
    fn test_builtin_cpu_policy_reads_the_devices_list() {
        let input = json!({"devices": [
            {"device": "sample", "tee": "sample", "claims": {"launch_digest": "good"}},
        ]});
        let trust_claims = eval_default_cpu_policy(input, "data.policy.trust_claims");
        assert_eq!(trust_claims["executables"], regorus::Value::from(3));

        let input = json!({"devices": [
            {"device": "sample", "tee": "sample", "claims": {"launch_digest": "bad"}},
        ]});
        let trust_claims = eval_default_cpu_policy(input, "data.policy.trust_claims");
        assert_eq!(trust_claims["executables"], regorus::Value::from(33));
    }

    #[test]
    fn test_builtin_cpu_policy_extensions_use_init_data_of_the_devices() {
        let input = json!({"devices": [{
            "device": "sample",
            "tee": "sample",
            "claims": {},
            "init_data_claims": {"agent_policy_claims": {"containers": [
                {"OCI": {
                    "Annotations": {"io.kubernetes.cri.image-name": "busybox"},
                    "Process": {"User": {"UID": 1000}},
                }},
            ]}},
        }]});
        let extensions = eval_default_cpu_policy(input, "data.policy.extensions");
        let extensions = serde_json::to_value(extensions).unwrap();
        assert_eq!(
            extensions[0]["value"]["validated"],
            json!({
                "pod-image": ["busybox"],
                "pod-image-count": 1,
                "container_uids": [1000],
            })
        );
    }

    #[tokio::test]
    async fn test_custom_and_builtin_policies_can_be_mixed() {
        // The built-in CPU policy needs reference values, replace it by a
        // custom policy. The built-in GPU policy is used as is.
        let broker =
            broker_with_policies(&[("my_cpu", counting_policy(&["sample"], "cpu0", 1))]).await;

        let token = broker
            .issue(
                vec![
                    device_claims(Tee::Sample, "sample", json!({})),
                    device_claims(Tee::Nvidia, "nvidia-gpu", trusted_gpu_claims()),
                    device_claims(Tee::Nvidia, "nvidia-gpu", trusted_gpu_claims()),
                ],
                vec!["my_cpu".into(), "default_gpu".into()],
                None,
            )
            .await
            .unwrap();
        // The two GPUs are judged together, they do not get one entry each.
        assert_eq!(submod_names(&token), ["cpu0", "gpu0"]);
    }

    #[tokio::test]
    async fn test_get_jwks() {
        let config = EarTokenConfiguration::default();
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let jwks = broker.get_jwks().unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(
            jwks.keys[0].common.key_algorithm,
            Some(jwk::KeyAlgorithm::ES256)
        );
        match &jwks.keys[0].algorithm {
            AlgorithmParameters::EllipticCurve(ec) => {
                assert_eq!(ec.curve, EllipticCurve::P256);
                let x = URL_SAFE_NO_PAD.decode(&ec.x).unwrap();
                let y = URL_SAFE_NO_PAD.decode(&ec.y).unwrap();
                assert_eq!(x.len(), 32, "x coordinate must be 32 bytes for P-256");
                assert_eq!(y.len(), 32, "y coordinate must be 32 bytes for P-256");
            }
            other => panic!("unexpected key type: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_get_jwks_matches_fixture() {
        let signer = TokenSignerConfig {
            key_path: "tests/fixtures/jwk/signing-key.pem".to_string(),
            cert_url: None,
            cert_path: Some("tests/fixtures/jwk/cert-chain.pem".to_string()),
        };

        let config = EarTokenConfiguration {
            signer: Some(signer),
            ..Default::default()
        };
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        let broker = EarAttestationTokenBroker::new(config, storage)
            .await
            .unwrap();

        let jwks = broker.get_jwks().unwrap();
        let expected: JwkSet =
            serde_json::from_str(include_str!("../../tests/fixtures/jwk/expected-jwks.json"))
                .unwrap();

        assert_eq!(jwks, expected);
    }
}
