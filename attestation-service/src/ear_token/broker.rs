// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Context, Error, Result};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ear::{Algorithm, Appraisal, Ear, Extensions, RawValue, RawValueKind, VerifierID};
use jsonwebtoken::jwk::{self, JwkSet};
use key_value_storage::KeyValueStorageInstance;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use policy_engine::rego::RegorusExtension;
use policy_engine::{rego::Regorus, PolicyEngine};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use time::{Duration as TimeDuration, OffsetDateTime};
use tracing::{debug, info, warn};

use crate::ear_token::claims::TransformedClaims;
use crate::ear_token::EarTokenConfiguration;
use crate::rvps::RvpsClient;
use crate::TeeClaims;

/// The policy claim that will hold trust claims.
pub const TRUST_CLAIMS_RULE: &str = "data.policy.trust_claims";
/// The policy claim that will hold extensions.
pub const EXTENSIONS_RULE: &str = "data.policy.extensions";

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
            .set_policy("default_cpu", default_cpu_policy, false)
            .await?;

        let default_gpu_policy = include_str!("ear_default_policy_gpu.rego");

        policy_engine
            .set_policy("default_gpu", default_gpu_policy, false)
            .await?;

        let default_switch_policy = include_str!("ear_default_policy_switch.rego");

        policy_engine
            .set_policy("default_switch", default_switch_policy, false)
            .await?;

        let default_ppcie_policy = include_str!("ear_default_policy_ppcie.rego");

        policy_engine
            .set_policy("default_ppcie", default_ppcie_policy, false)
            .await?;

        if config.signer.is_none() {
            info!("No Token Signer key in config file, create an ephemeral key and without CA pubkey cert");
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
    pub async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        rvps_client: Option<RvpsClient>,
    ) -> Result<String> {
        if policy_ids.len() > 1 {
            warn!("EAR token only accepts the first policy. The rest will be ignored.");
        }

        if policy_ids.is_empty() {
            bail!("No policy is given for EAR token generation.");
        }

        let mut tee_class_indices: HashMap<String, u8> = HashMap::new();
        let mut submods = BTreeMap::new();

        // Create an appraisal for each device
        for tee_claims in all_tee_claims {
            let mut appraisal = Appraisal::new();

            let transformed_claims = TransformedClaims::new(
                tee_claims.claims,
                tee_claims.init_data_claims.clone(),
                tee_claims.runtime_data_claims.clone(),
                tee_claims.tee,
                self.config.verbose_token,
            )?;

            let tcb_claims_json = transformed_claims.policy_input_json()?;

            // There is a policy for each tee class.
            // The cpu tee class is loaded as the default.
            let policy_id = format!("{}_{}", policy_ids[0], tee_claims.tee_class);
            let mut extensions = vec![];
            if let Some(ref rvps_client) = rvps_client {
                let rvps_client = rvps_client.clone();
                let extension = RegorusExtension {
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
                                .map_err(|e| {
                                    anyhow!("Get Reference Value from RVPS timeout: {e:?}")
                                })?
                            })
                            .map_err(|e| anyhow!("Get Reference Value from RVPS failed: {e:?}"))?;

                        match result {
                            Some(v) => {
                                let json_value = serde_json::to_value(v)?;
                                let value: regorus::Value = serde_json::from_value(json_value)?;
                                Ok(value)
                            }
                            None => {
                                warn!("No reference value found for the given id: {id}, use NULL as the returned value");
                                Ok(regorus::Value::Null)
                            }
                        }
                    }),
                };

                extensions.push(extension);
            }

            let policy_results = self
                .policy_engine
                .evaluate_rego(
                    None,
                    tcb_claims_json,
                    &policy_id,
                    vec![TRUST_CLAIMS_RULE.to_string(), EXTENSIONS_RULE.to_string()],
                    extensions,
                )
                .await?;

            match policy_results
                .eval_rules_result
                .get(TRUST_CLAIMS_RULE)
                .with_context(|| {
                    format!(
                        "Trust claims rule {TRUST_CLAIMS_RULE} not found for policy {policy_id}"
                    )
                })? {
                Some(value) => {
                    let trust_claims =
                        value.as_object().context("Trust claims is not an object")?;
                    for (k, v) in trust_claims {
                        let claim_value = v.as_i64().context("Trust claim value not number")?;
                        debug!("Trust claim: {}: {}", k, claim_value);

                        appraisal
                            .trust_vector
                            .mut_by_name(k)
                            .unwrap()
                            .set(claim_value as i8);
                    }
                }
                None => {
                    warn!("No trust claims found by enforcing policy {policy_id}, set all TrustVector claims to 0");
                    appraisal.trust_vector.set_all(0);
                }
            }

            if !appraisal.trust_vector.any_set() {
                bail!("At least one policy claim must be set.");
            }

            // Policy-authored fields from data.policy.extensions land in
            // ear_verifier_claims.custom (EAR draft-04).
            let extension_claims = policy_results
                .eval_rules_result
                .get(EXTENSIONS_RULE)
                .context("Extensions rule not found")?
                .as_ref()
                .cloned()
                .unwrap_or(json!([]));

            let extension_claims = serde_json::from_value::<Vec<TokenExtension>>(extension_claims)
                .context("Illegal extensions rule in policy.")?;

            let custom_claims = extension_claims
                .into_iter()
                .map(|extension| (extension.name, extension.value))
                .collect();

            appraisal.attester_claims = transformed_claims.attester_claims()?.into_raw_map()?;
            appraisal.verifier_claims = transformed_claims
                .verifier_claims(custom_claims)
                .into_raw_map()?;
            appraisal.policy_ids = vec![policy_ids[0].clone()];
            appraisal.update_status_from_trust_vector();

            if let Some(index) = tee_class_indices.get_mut(&tee_claims.tee_class) {
                *index += 1;
            } else {
                tee_class_indices.insert(tee_claims.tee_class.clone(), 0);
            }

            let submod_name = format!(
                "{}{}",
                tee_claims.tee_class,
                // We know this key will exist because of the logic above.
                tee_class_indices.get(&tee_claims.tee_class).unwrap()
            );
            submods.insert(submod_name, appraisal);
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

    pub async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
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
    use jsonwebtoken::DecodingKey;
    use kbs_types::Tee;
    use key_value_storage::{KeyValueStorageStructConfig, KeyValueStorageType, SetParameters};
    use serde_json::json;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::{ear_token::TokenSignerConfig, TeeClaims, AS_POLICY_STORAGE_NAMESPACE};

    use super::*;

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
                "ear_no_rv_policy_cpu.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego"),
                SetParameters { overwrite: true },
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
                    tee_class: "cpu".to_string(),
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

        let mut config = EarTokenConfiguration::default();
        config.signer = Some(signer);
        let storage = KeyValueStorageStructConfig::default()
            .to_client_with_namespace(KeyValueStorageType::Memory, AS_POLICY_STORAGE_NAMESPACE)
            .await
            .unwrap();
        storage
            .set(
                "ear_no_rv_policy_cpu.rego",
                include_bytes!("../../tests/coco-as/policy/opa/ear_no_rv_policy_cpu.rego"),
                SetParameters { overwrite: true },
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
                    tee_class: "cpu".to_string(),
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

        let mut config = EarTokenConfiguration::default();
        config.signer = Some(signer);
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
