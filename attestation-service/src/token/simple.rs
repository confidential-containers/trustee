// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! # Simple Token Broker
//!
//! This is an implementation of Token Broker that uses OPA for
//! policy evaluation.

use anyhow::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use log::info;
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::X509;
use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Private},
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use serde_variant::to_variant_name;
use shadow_rs::concatcp;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::policy_engine::{PolicyEngine, PolicyEngineType};
use crate::token::{AttestationTokenBroker, DEFAULT_TOKEN_WORK_DIR};
use crate::{RvpsApi, TeeClaims, TeeEvidenceParsedClaim};

use super::{COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION};

const RSA_KEY_BITS: u32 = 2048;
const SIMPLE_TOKEN_ALG: &str = "RS384";

const DEFAULT_POLICY_DIR: &str = concatcp!(DEFAULT_TOKEN_WORK_DIR, "/simple/policies");

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenSignerConfig {
    pub key_path: String,
    pub cert_url: Option<String>,

    // PEM format certificate chain.
    pub cert_path: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Configuration {
    /// The Attestation Results Token duration time (in minutes)
    /// Default: 5 minutes
    #[serde(default = "default_duration")]
    pub duration_min: i64,

    /// the issuer of the token
    #[serde(default = "default_issuer_name")]
    pub issuer_name: String,

    /// Configuration for signing the token.
    /// If this is not specified, the token
    /// will be signed with an ephemeral private key.
    pub signer: Option<TokenSignerConfig>,

    /// The path to the work directory that contains policies
    /// to provision the tokens.
    #[serde(default = "default_policy_dir")]
    pub policy_dir: String,
}

#[inline]
fn default_duration() -> i64 {
    DEFAULT_TOKEN_DURATION
}

#[inline]
fn default_issuer_name() -> String {
    COCO_AS_ISSUER_NAME.to_string()
}

#[inline]
fn default_policy_dir() -> String {
    DEFAULT_POLICY_DIR.to_string()
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            duration_min: default_duration(),
            issuer_name: default_issuer_name(),
            signer: None,
            policy_dir: default_policy_dir(),
        }
    }
}

pub struct SimpleAttestationTokenBroker {
    private_key: Rsa<Private>,
    config: Configuration,
    cert_url: Option<String>,
    cert_chain: Option<Vec<X509>>,
    policy_engine: Arc<dyn PolicyEngine>,
}

impl SimpleAttestationTokenBroker {
    pub fn new(config: Configuration, rvps: Arc<Mutex<dyn RvpsApi + Send + Sync>>) -> Result<Self> {
        let policy_engine = PolicyEngineType::OPA.to_policy_engine(
            Path::new(&config.policy_dir),
            include_str!("simple_default_policy.rego"),
            "default.rego",
            rvps,
        )?;
        info!("Loading default AS policy \"simple_default_policy.rego\"");

        if config.signer.is_none() {
            log::info!("No Token Signer key in config file, create an ephemeral key and without CA pubkey cert");
            return Ok(Self {
                private_key: Rsa::generate(RSA_KEY_BITS)?,
                config,
                cert_url: None,
                cert_chain: None,
                policy_engine,
            });
        }

        let signer = config.signer.clone().unwrap();
        let pem_data = std::fs::read(&signer.key_path)
            .map_err(|e| anyhow!("Read Token Signer private key failed: {:?}", e))?;
        let private_key = Rsa::private_key_from_pem(&pem_data)?;

        let cert_chain = signer
            .cert_path
            .as_ref()
            .map(|cert_path| -> Result<Vec<X509>> {
                let pem_cert_chain = std::fs::read_to_string(cert_path)
                    .map_err(|e| anyhow!("Read Token Signer cert file failed: {:?}", e))?;
                let mut chain = Vec::new();

                for pem in pem_cert_chain.split("-----END CERTIFICATE-----") {
                    let trimmed = format!("{}\n-----END CERTIFICATE-----", pem.trim());
                    if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
                        continue;
                    }
                    let cert = X509::from_pem(trimmed.as_bytes())
                        .map_err(|_| anyhow!("Invalid PEM certificate chain"))?;
                    chain.push(cert);
                }
                Ok(chain)
            })
            .transpose()?;

        Ok(Self {
            private_key,
            config,
            cert_url: signer.cert_url,
            cert_chain,
            policy_engine,
        })
    }
}

impl SimpleAttestationTokenBroker {
    fn rs384_sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let rsa_pkey = PKey::from_rsa(self.private_key.clone())?;
        let mut signer = Signer::new(MessageDigest::sha384(), &rsa_pkey)?;
        signer.update(payload)?;
        let signature = signer.sign_to_vec()?;

        Ok(signature)
    }

    fn pubkey_jwks(&self) -> Result<String> {
        let n = self.private_key.n().to_vec();
        let e = self.private_key.e().to_vec();

        let mut jwk = Jwk {
            kty: "RSA".to_string(),
            alg: SIMPLE_TOKEN_ALG.to_string(),
            n: URL_SAFE_NO_PAD.encode(n),
            e: URL_SAFE_NO_PAD.encode(e),
            x5u: None,
            x5c: None,
        };

        jwk.x5u.clone_from(&self.cert_url);
        if let Some(cert_chain) = self.cert_chain.clone() {
            let mut x5c = Vec::new();
            for cert in cert_chain {
                let der = cert.to_der()?;
                x5c.push(URL_SAFE_NO_PAD.encode(der));
            }
            jwk.x5c = Some(x5c);
        }

        let jwks = json!({
            "keys": vec![jwk],
        });

        Ok(serde_json::to_string(&jwks)?)
    }
}

#[async_trait::async_trait]
impl AttestationTokenBroker for SimpleAttestationTokenBroker {
    async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_data_map: HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        // Take claims from all verifiers, flatten them and add them to one map.
        let mut flattened_claims: Map<String, Value> = Map::new();
        for tee_claims in &all_tee_claims {
            flattened_claims.append(&mut flatten_claims(tee_claims.tee, &tee_claims.claims)?);
        }

        let reference_data = json!({
            "reference": reference_data_map,
        });
        let reference_data = serde_json::to_string(&reference_data)?;
        let tcb_claims = serde_json::to_string(&flattened_claims)?;

        let rules = vec!["allow".to_string()];

        let mut policies = HashMap::new();
        for policy_id in policy_ids {
            let policy_results = self
                .policy_engine
                .evaluate(&reference_data, &tcb_claims, &policy_id, rules.clone())
                .await?;

            // TODO add policy allowlist
            let Some(result) = policy_results.rules_result.get("allow") else {
                bail!("Policy results must contain `allow` claim");
            };

            let result = result
                .as_bool()
                .context("value `allow` must be a bool in policy")?;
            if !result {
                bail!("Reject by policy {policy_id}");
            }

            policies.insert(policy_id, policy_results.policy_hash);
        }

        let policies: Vec<_> = policies
            .into_iter()
            .map(|(k, v)| {
                json!({
                    "policy-id": k,
                    "policy-hash": v,
                })
            })
            .collect();

        let token_claims = json!({
            "tee": to_variant_name(&all_tee_claims[0].tee)?,
            "evaluation-reports": policies,
            "tcb-status": tcb_claims,
            "customized_claims": {
                "init_data": all_tee_claims[0].init_data_claims,
                "runtime_data": all_tee_claims[0].runtime_data_claims,
            },
        });

        let header_value = json!({
            "typ": "JWT",
            "alg": SIMPLE_TOKEN_ALG,
            "jwk": serde_json::from_str::<Value>(&self.pubkey_jwks()?)?["keys"][0].clone(),
        });
        let header_string = serde_json::to_string(&header_value)?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_string.as_bytes());

        let now = time::OffsetDateTime::now_utc();
        let exp = now + time::Duration::minutes(self.config.duration_min);

        let id: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

        let mut jwt_claims = json!({
            "iss": self.config.issuer_name.clone(),
            "iat": now.unix_timestamp(),
            "jti": id,
            "nbf": now.unix_timestamp(),
            "exp": exp.unix_timestamp(),
        })
        .as_object()
        .ok_or_else(|| anyhow!("Internal Error: generate claims failed"))?
        .clone();

        jwt_claims.extend(
            token_claims
                .as_object()
                .ok_or_else(|| anyhow!("Illegal token custom claims"))?
                .to_owned(),
        );

        let claims_value = Value::Object(jwt_claims);
        let claims_string = serde_json::to_string(&claims_value)?;
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims_string.as_bytes());

        let signature_payload = format!("{header_b64}.{claims_b64}");
        let signature = self.rs384_sign(signature_payload.as_bytes())?;
        let signature_b64 = URL_SAFE_NO_PAD.encode(signature);

        let token = format!("{signature_payload}.{signature_b64}");

        Ok(token)
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
        self.policy_engine
            .set_policy(policy_id, policy)
            .await
            .map_err(Error::from)
    }

    async fn list_policies(&self) -> Result<HashMap<String, String>> {
        self.policy_engine
            .list_policies()
            .await
            .map_err(Error::from)
    }

    async fn get_policy(&self, policy_id: String) -> Result<String> {
        self.policy_engine
            .get_policy(policy_id)
            .await
            .map_err(Error::from)
    }
}

#[derive(serde::Serialize, Debug, Clone)]
struct Jwk {
    kty: String,
    alg: String,
    n: String,
    e: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
}

/// This funciton will transpose the following structured json
/// ```json
/// {
///     "a" : {
///         "b": "c"
///     },
///     "d": "e"
/// }
/// ```
/// into a flatten one with '.' to separate and also be added a prefix of tee name, e.g.
/// ```json
/// {
///     "sample.a.b": "c",
///     "sample.d": "e"
/// }
/// ```
///
/// But the key `init_data` and `report_data` will not be added the prefix.
fn flatten_claims(
    tee: kbs_types::Tee,
    claims: &TeeEvidenceParsedClaim,
) -> Result<Map<String, Value>> {
    let mut map = Map::new();
    let tee_type = to_variant_name(&tee)?;
    match claims {
        Value::Object(obj) => {
            for (k, v) in obj {
                if k != "report_data" && k != "init_data" {
                    flatten_helper(&mut map, v, format!("{tee_type}.{}", k.clone()));
                }
            }
            let report_data = obj
                .get("report_data")
                .cloned()
                .unwrap_or(Value::String(String::new()));
            map.insert("report_data".to_string(), report_data.clone());

            let report_data = obj
                .get("init_data")
                .cloned()
                .unwrap_or(Value::String(String::new()));
            map.insert("init_data".to_string(), report_data.clone());
        }
        _ => bail!("input claims must be a map"),
    }

    Ok(map)
}

/// Recursion algorithm helper of `flatten_claims`
fn flatten_helper(parent: &mut Map<String, Value>, child: &serde_json::Value, prefix: String) {
    match child {
        Value::Null => {
            let _ = parent.insert(prefix, Value::Null);
        }
        Value::Bool(v) => {
            let _ = parent.insert(prefix, Value::Bool(*v));
        }
        Value::Number(v) => {
            let _ = parent.insert(prefix, Value::Number(v.clone()));
        }
        Value::String(str) => {
            let _ = parent.insert(prefix, Value::String(str.clone()));
        }
        Value::Array(arr) => {
            let _ = parent.insert(prefix, Value::Array(arr.clone()));
        }
        Value::Object(obj) => {
            for (k, v) in obj {
                let sub_prefix = format!("{prefix}.{k}");
                flatten_helper(parent, v, sub_prefix);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::TeeClaims;
    use assert_json_diff::assert_json_eq;
    use kbs_types::Tee;
    use serde_json::json;

    use crate::token::{
        simple::{Configuration, SimpleAttestationTokenBroker},
        AttestationTokenBroker,
    };

    use super::flatten_claims;

    #[tokio::test]
    async fn test_issue_simple_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = Configuration::default();
        let broker = SimpleAttestationTokenBroker::new(config).unwrap();

        let _token = broker
            .issue(
                vec![TeeClaims {
                    tee: Tee::Sample,
                    tee_class: "cpu".to_string(),
                    claims: json!({"claim": "claim1"}),
                    runtime_data_claims: json!({"runtime_data": "111"}),
                    init_data_claims: json!({"initdata": "111"}),
                }],
                vec!["default".into()],
                HashMap::new(),
            )
            .await
            .unwrap();
    }

    #[test]
    fn flatten() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": null
                }
            },
            "quote": {
                "header":{
                    "version": "0400",
                    "att_key_type": "0200",
                    "tee_type": "81000000",
                    "reserved": "00000000",
                    "vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                    "user_data": "d099bfec0a477aa85a605dceabf2b10800000000"
                },
                "body":{
                    "mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                    "mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                    "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                    "seam_attributes": "0000000000000000",
                    "td_attributes": "0100001000000000",
                    "mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                    "tcb_svn": "03000500000000000000000000000000",
                    "xfam": "e742060000000000"
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        let flatten = flatten_claims(kbs_types::Tee::Tdx, &json).expect("flatten failed");
        let expected = json!({
                "tdx.ccel.kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "tdx.ccel.kernel_parameters.console": "hvc0",
                "tdx.ccel.kernel_parameters.root": "/dev/vda1",
                "tdx.ccel.kernel_parameters.rw": null,
                "tdx.quote.header.version": "0400",
                "tdx.quote.header.att_key_type": "0200",
                "tdx.quote.header.tee_type": "81000000",
                "tdx.quote.header.reserved": "00000000",
                "tdx.quote.header.vendor_id": "939a7233f79c4ca9940a0db3957f0607",
                "tdx.quote.header.user_data": "d099bfec0a477aa85a605dceabf2b10800000000",
                "tdx.quote.body.mr_config_id": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_owner": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_owner_config": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.mr_td": "705ee9381b8633a9fbe532b52345e8433343d2868959f57889d84ca377c395b689cac1599ccea1b7d420483a9ce5f031",
                "tdx.quote.body.mrsigner_seam": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "tdx.quote.body.report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "tdx.quote.body.seam_attributes": "0000000000000000",
                "tdx.quote.body.td_attributes": "0100001000000000",
                "tdx.quote.body.mr_seam": "2fd279c16164a93dd5bf373d834328d46008c2b693af9ebb865b08b2ced320c9a89b4869a9fab60fbe9d0c5a5363c656",
                "tdx.quote.body.tcb_svn": "03000500000000000000000000000000",
                "tdx.quote.body.xfam": "e742060000000000",
                "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
                "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });
        assert_json_eq!(expected, flatten);
    }
}
