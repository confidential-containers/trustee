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
    use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType};
    use serde_json::json;

    use crate::{AS_POLICY_STORAGE_NAMESPACE, ear_token::TokenSignerConfig};

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
