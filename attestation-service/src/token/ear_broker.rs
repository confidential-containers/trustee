// Copyright (c) 2024 IBM
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::*;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ear::{Algorithm, Appraisal, Ear, Extensions, RawValue, RawValueKind, VerifierID};
use jsonwebtoken::jwk;
use kbs_types::Tee;
use log::{debug, warn};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use serde::Deserialize;
use serde_json::{json, Value};
use serde_variant::to_variant_name;
use shadow_rs::concatcp;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

use crate::policy_engine::{PolicyEngine, PolicyEngineType};
use crate::token::DEFAULT_TOKEN_WORK_DIR;
use crate::{AttestationTokenBroker, TeeClaims};

use super::{COCO_AS_ISSUER_NAME, DEFAULT_TOKEN_DURATION};

pub const DEFAULT_PROFILE: &str = "tag:github.com,2024:confidential-containers/Trustee";
pub const DEFAULT_DEVELOPER_NAME: &str = "https://confidentialcontainers.org";

const DEFAULT_POLICY_DIR: &str = concatcp!(DEFAULT_TOKEN_WORK_DIR, "/ear/policies");

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct TokenSignerConfig {
    pub key_path: String,
    #[serde(default = "Option::default")]
    pub cert_url: Option<String>,

    // PEM format certificate chain.
    #[serde(default = "Option::default")]
    pub cert_path: Option<String>,
}

#[derive(Deserialize, Debug, Clone, PartialEq)]
pub struct Configuration {
    /// The Attestation Results Token duration time (in minutes)
    /// Default: 5 minutes
    #[serde(default = "default_duration")]
    pub duration_min: i64,

    /// For tokens, the issuer of the token
    #[serde(default = "default_issuer_name")]
    pub issuer_name: String,

    /// The developer name to be used as part of the Verifier ID
    /// in the EAR.
    /// Default: `https://confidentialcontainers.org`
    #[serde(default = "default_developer")]
    pub developer_name: String,

    /// The build name to be used as part of the Verifier ID
    /// in the EAR.
    /// The default value will be generated from the Cargo package
    /// name and version of the AS.
    #[serde(default = "default_build")]
    pub build_name: String,

    /// The Profile that describes the EAR token
    /// Default: `tag:github.com,2024:confidential-containers/Trustee`
    #[serde(default = "default_profile")]
    pub profile_name: String,

    /// Configuration for signing the EAR
    /// If this is not specified, the EAR
    /// will be signed with an ephemeral private key.
    #[serde(default = "Option::default")]
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
fn default_developer() -> String {
    DEFAULT_DEVELOPER_NAME.to_string()
}

#[inline]
fn default_profile() -> String {
    DEFAULT_PROFILE.to_string()
}

#[inline]
fn default_build() -> String {
    format!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
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
            developer_name: default_developer(),
            build_name: default_build(),
            profile_name: default_profile(),
            signer: None,
            policy_dir: default_policy_dir(),
        }
    }
}

pub struct EarAttestationTokenBroker {
    config: Configuration,
    private_key: EcKey<Private>,
    cert_url: Option<String>,
    cert_chain: Option<Vec<X509>>,
    policy_engine: Arc<dyn PolicyEngine>,
}

impl EarAttestationTokenBroker {
    pub async fn new(config: Configuration) -> Result<Self> {
        let policy_engine =
            PolicyEngineType::OPA.to_policy_engine(Path::new(&config.policy_dir))?;

        let default_cpu_policy = include_str!("ear_default_policy_cpu.rego").to_string();
        let default_cpu_policy =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(default_cpu_policy);

        policy_engine
            .set_policy("default_cpu".to_string(), default_cpu_policy, false)
            .await?;

        let default_gpu_policy = include_str!("ear_default_policy_gpu.rego").to_string();
        let default_gpu_policy =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(default_gpu_policy);

        policy_engine
            .set_policy("default_gpu".to_string(), default_gpu_policy, false)
            .await?;

        if config.signer.is_none() {
            log::info!("No Token Signer key in config file, create an ephemeral key and without CA pubkey cert");
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
            config,
            private_key,
            cert_url: signer.cert_url,
            cert_chain,
            policy_engine,
        })
    }
}

#[async_trait::async_trait]
impl AttestationTokenBroker for EarAttestationTokenBroker {
    async fn issue(
        &self,
        all_tee_claims: Vec<TeeClaims>,
        policy_ids: Vec<String>,
        reference_data_map: HashMap<String, serde_json::Value>,
    ) -> Result<String> {
        debug!("all_tee_claims: {:#?}", all_tee_claims);

        let reference_data = json!({
            "reference": reference_data_map,
        });
        let reference_data = serde_json::to_string(&reference_data)?;

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

            let tcb_claims = transform_claims(
                tee_claims.claims,
                tee_claims.init_data_claims.clone(),
                tee_claims.runtime_data_claims.clone(),
                tee_claims.tee,
            )?;

            let tcb_claims_json = serde_json::to_string(&tcb_claims)?;

            // There is a policy for each tee class.
            // The cpu tee class is loaded as the default.
            let policy_id = format!("{}_{}", policy_ids[0], tee_claims.tee_class);
            let policy_results = self
                .policy_engine
                .evaluate(&reference_data, &tcb_claims_json, &policy_id)
                .await?;

            let result = policy_results
                .rules_result
                .as_object()
                .context("Policy result is not an object")?;

            for (k, v) in result {
                let claim_value = v.as_i64().context("Policy claim value not number")?;
                debug!("Policy claim: {}: {}", k, claim_value);

                appraisal
                    .trust_vector
                    .mut_by_name(k)
                    .unwrap()
                    .set(claim_value as i8);
            }

            if !appraisal.trust_vector.any_set() {
                bail!("At least one policy claim must be set.");
            }

            appraisal.update_status_from_trust_vector();
            appraisal.annotated_evidence = tcb_claims;
            appraisal.policy_id = Some(policy_ids[0].clone());

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
        let exp = now
            .checked_add(Duration::minutes(self.config.duration_min))
            .ok_or(anyhow!("Token expiration overflow."))?;

        let mut extensions = Extensions::new();
        extensions.register("exp", 4, RawValueKind::Integer)?;
        extensions.set_by_name("exp", RawValue::Integer(exp.unix_timestamp()))?;

        let ear = Ear {
            profile: self.config.profile_name.clone(),
            iat: now.unix_timestamp(),
            vid: VerifierID {
                build: self.config.build_name.clone(),
                developer: self.config.developer_name.clone(),
            },
            raw_evidence: None,
            nonce: None,
            submods,
            extensions,
        };
        let mut jwt_header = ear::new_jwt_header(&Algorithm::ES256)?;
        jwt_header.jwk = Some(self.pubkey_jwk()?);

        let pkey = PKey::from_ec_key(self.private_key.clone())?;
        let private_key_bytes = pkey.private_key_to_pem_pkcs8()?;

        let signed_ear = ear.sign_jwt_pem_with_header(&jwt_header, &private_key_bytes)?;

        Ok(signed_ear)
    }

    async fn set_policy(&self, policy_id: String, policy: String) -> Result<()> {
        self.policy_engine
            .set_policy(policy_id, policy, true)
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

impl EarAttestationTokenBroker {
    // TODO: converge this with the jwk function in the simple token broker
    fn pubkey_jwk(&self) -> Result<jwk::Jwk> {
        let chain = self
            .cert_chain
            .as_ref()
            .map(|certs| -> Result<Vec<String>> {
                let mut chain = vec![];
                for cert in certs {
                    let der = cert.to_der()?;
                    chain.push(URL_SAFE_NO_PAD.encode(der));
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

        let algorithm = jwk::AlgorithmParameters::EllipticCurve(jwk::EllipticCurveKeyParameters {
            key_type: jwk::EllipticCurveKeyType::EC,
            curve: jwk::EllipticCurve::P256,
            x: URL_SAFE_NO_PAD.encode(x.to_vec()),
            y: URL_SAFE_NO_PAD.encode(y.to_vec()),
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

/// This function does three things.
///
/// 1) If the input claims include an init_data claim (meaning that
///    the verifier has validated the init_data), add the JSON
///    init_data_claims to the output claims. Do the same thing
///    for the report_data and runtime_data_claims.
///
///    This means that the full init_data and report_data will be
///    available in the token.
///
/// 2) Move all claims from input_claims except the ones mentioned
///    in the previous step into their own Object under the tee name.
///
/// 3) Convert the claims from serde_json Values to RawValues from the
///    EAR crate.
///
pub fn transform_claims(
    mut input_claims: Value,
    init_data_claims: Value,
    runtime_data_claims: Value,
    tee: Tee,
) -> Result<BTreeMap<String, RawValue>> {
    let mut output_claims = BTreeMap::new();

    // If the verifier produces an init_data claim (meaning that
    // it has validated the init_data hash), add the JSON init_data_claims,
    // to the claims map. Do the same for the report data.
    //
    // These claims will be flattened and provided to the policy engine.
    // They will also end up in the EAR token as part of the annotated evidence.
    if let Some(claims_map) = input_claims.as_object_mut() {
        if let Some(init_data) = claims_map.remove("init_data") {
            output_claims.insert(
                "init_data".to_string(),
                RawValue::String(init_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&init_data_claims)?)?;
            output_claims.insert("init_data_claims".to_string(), transformed_claims);
        }

        if let Some(report_data) = claims_map.remove("report_data") {
            output_claims.insert(
                "report_data".to_string(),
                RawValue::String(report_data.as_str().unwrap().to_string()),
            );

            let transformed_claims: RawValue =
                serde_json::from_str(&serde_json::to_string(&runtime_data_claims)?)?;
            output_claims.insert("runtime_data_claims".to_string(), transformed_claims);
        }
    }

    let transformed_claims: RawValue =
        serde_json::from_str(&serde_json::to_string(&input_claims)?)?;
    output_claims.insert(to_variant_name(&tee)?.to_string(), transformed_claims);

    Ok(output_claims)
}

#[cfg(test)]
mod tests {
    use assert_json_diff::assert_json_eq;
    use jsonwebtoken::DecodingKey;
    use std::io::Write;
    use tempfile::NamedTempFile;

    use crate::TeeClaims;

    use super::*;

    #[tokio::test]
    async fn test_issue_ear_ephemeral_key() {
        // use default config with no signer.
        // this will sign the token with an ephemeral key.
        let config = Configuration::default();
        let broker = EarAttestationTokenBroker::new(config).await.unwrap();

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

        let mut config = Configuration::default();
        config.signer = Some(signer);

        let broker = EarAttestationTokenBroker::new(config).await.unwrap();
        let token = broker
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

        let public_key = DecodingKey::from_ec_pem(&public_key_bytes).unwrap();

        let ear = Ear::from_jwt(&token, jsonwebtoken::Algorithm::ES256, &public_key).unwrap();
        ear.validate().unwrap();
    }

    #[test]
    fn test_transform_claims() {
        let json = json!({
            "ccel": {
                "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                "kernel_parameters": {
                    "console": "hvc0",
                    "root": "/dev/vda1",
                    "rw": ""
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

        let init_data_claims = Value::String("".to_string());
        let runtime_data_claims = Value::String("".to_string());
        let transformed_claims =
            transform_claims(json, init_data_claims, runtime_data_claims, Tee::Tdx)
                .expect("flatten failed");

        let expected_claims = json!({
            "tdx": {
                "ccel": {
                    "kernel": "5b7aa6572f649714ff00b6a2b9170516a068fd1a0ba72aa8de27574131d454e6396d3bfa1727d9baf421618a942977fa",
                    "kernel_parameters": {
                        "console": "hvc0",
                        "root": "/dev/vda1",
                        "rw": ""
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
                }
            },
            "report_data": "7c71fe2c86eff65a7cf8dbc22b3275689fd0464a267baced1bf94fc1324656aeb755da3d44d098c0c87382f3a5f85b45c8a28fee1d3bdb38342bf96671501429",
            "init_data": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "runtime_data_claims": "",
            "init_data_claims": ""
        });

        assert_json_eq!(expected_claims, transformed_claims);
    }
}
