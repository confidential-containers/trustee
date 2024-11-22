// Copyright (c) 2024 by Intel Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::token::AttestationTokenVerifierConfig;
use anyhow::{anyhow, bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk};
use jsonwebtoken::{decode, decode_header, jwk, Algorithm, DecodingKey, Header, Validation};
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::X509StoreContext;
use openssl::{rsa::Rsa, x509::X509};
use reqwest::{get, Url};
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::BufReader;
use std::result::Result::Ok;
use std::str::FromStr;
use thiserror::Error;
use tokio::fs;

const OPENID_CONFIG_URL_SUFFIX: &str = ".well-known/openid-configuration";

#[derive(Error, Debug)]
pub enum JwksGetError {
    #[error("Invalid source path: {0}")]
    InvalidSourcePath(String),
    #[error("Failed to access source: {0}")]
    AccessFailed(String),
    #[error("Failed to deserialize source data: {0}")]
    DeserializeSource(String),
}

#[derive(Deserialize)]
struct OpenIDConfig {
    jwks_uri: String,
}

#[derive(Clone)]
pub struct JwkAttestationTokenVerifier {
    trusted_jwk_sets: jwk::JwkSet,
    trusted_certs: Vec<X509>,
    insecure_key: bool,
}

async fn get_jwks_from_file_or_url(p: &str) -> Result<jwk::JwkSet, JwksGetError> {
    let mut url = Url::parse(p).map_err(|e| JwksGetError::InvalidSourcePath(e.to_string()))?;
    match url.scheme() {
        "https" => {
            url.set_path(OPENID_CONFIG_URL_SUFFIX);

            let oidc = get(url.as_str())
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                .json::<OpenIDConfig>()
                .await
                .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))?;

            let jwkset = get(oidc.jwks_uri)
                .await
                .map_err(|e| JwksGetError::AccessFailed(e.to_string()))?
                .json::<jwk::JwkSet>()
                .await
                .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))?;

            Ok(jwkset)
        }
        "file" => {
            let file = File::open(url.path())
                .map_err(|e| JwksGetError::AccessFailed(format!("open {}: {}", url.path(), e)))?;

            serde_json::from_reader(BufReader::new(file))
                .map_err(|e| JwksGetError::DeserializeSource(e.to_string()))
        }
        _ => Err(JwksGetError::InvalidSourcePath(format!(
            "unsupported scheme {} (must be either file or https)",
            url.scheme()
        ))),
    }
}

impl JwkAttestationTokenVerifier {
    pub async fn new(config: &AttestationTokenVerifierConfig) -> anyhow::Result<Self> {
        let mut trusted_jwk_sets = jwk::JwkSet { keys: Vec::new() };

        for path in config.trusted_jwk_sets.iter() {
            match get_jwks_from_file_or_url(path).await {
                Ok(mut jwkset) => trusted_jwk_sets.keys.append(&mut jwkset.keys),
                Err(e) => log::warn!("error getting JWKS: {:?}", e),
            }
        }

        let mut trusted_certs = Vec::new();
        for path in &config.trusted_certs_paths {
            let cert_content = fs::read(path).await.map_err(|_| {
                JwksGetError::AccessFailed(format!("failed to read certificate {path}"))
            })?;
            let cert = X509::from_pem(&cert_content)?;
            trusted_certs.push(cert);
        }

        Ok(Self {
            trusted_jwk_sets,
            trusted_certs,
            insecure_key: config.insecure_key,
        })
    }

    fn verify_jwk_endorsement(&self, key: &Jwk) -> anyhow::Result<()> {
        let public_key = match &key.algorithm {
            AlgorithmParameters::RSA(rsa) => {
                let n = URL_SAFE_NO_PAD
                    .decode(&rsa.n)
                    .context("decode RSA public key parameter n")?;
                let n = BigNum::from_slice(&n)?;
                let e = URL_SAFE_NO_PAD
                    .decode(&rsa.e)
                    .context("decode RSA public key parameter e")?;
                let e = BigNum::from_slice(&e)?;

                let rsa_key = Rsa::from_public_components(n, e)?;
                PKey::from_rsa(rsa_key)?
            }
            AlgorithmParameters::EllipticCurve(ec) => {
                let x = BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&ec.x)?)?;
                let y = BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&ec.y)?)?;

                let group = match ec.curve {
                    EllipticCurve::P256 => EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?,
                    _ => bail!("Unsupported elliptic curve"),
                };

                let mut ctx = BigNumContext::new()?;
                let mut point = EcPoint::new(&group)?;
                point.set_affine_coordinates_gfp(&group, &x, &y, &mut ctx)?;

                let ec_key = EcKey::from_public_key(&group, &point)?;
                PKey::from_ec_key(ec_key)?
            }
            _ => bail!("Only RSA or EC JWKs are supported."),
        };

        let Some(x5c) = &key.common.x509_chain else {
            bail!("No x5c extension inside JWK. Invalid public key.")
        };

        if x5c.is_empty() {
            bail!("Empty x5c extension inside JWK. Invalid public key.")
        }

        let pem = x5c[0].split('\n').collect::<String>();
        let der = URL_SAFE_NO_PAD.decode(pem).context("Illegal x5c cert")?;

        let leaf_cert = X509::from_der(&der).context("Invalid x509 in x5c")?;
        // verify the public key matches the leaf cert
        if !public_key.public_eq(leaf_cert.public_key()?.as_ref()) {
            bail!("jwk does not match x5c");
        };

        let mut cert_chain = Stack::new()?;
        for cert in &x5c[1..] {
            let pem = cert.split('\n').collect::<String>();
            let der = URL_SAFE_NO_PAD.decode(&pem).context("Illegal x5c cert")?;

            let cert = X509::from_der(&der).context("Invalid x509 in x5c")?;
            cert_chain.push(cert)?;
        }

        let mut trust_store_builder = X509StoreBuilder::new()?;
        for cert in &self.trusted_certs {
            trust_store_builder.add_cert(cert.clone())?;
        }
        let trust_store = trust_store_builder.build();

        // verify the cert chain
        let mut ctx = X509StoreContext::new()?;
        if !ctx.init(&trust_store, &leaf_cert, &cert_chain, |c| c.verify_cert())? {
            bail!("JWK cannot be validated by trust anchor");
        }
        Ok(())
    }

    fn get_verification_jwk<'a>(&'a self, header: &'a Header) -> anyhow::Result<&'a Jwk> {
        if let Some(key) = &header.jwk {
            if self.insecure_key {
                return Ok(key);
            }
            if self.trusted_certs.is_empty() {
                bail!("Cannot verify token since trusted cert is empty");
            };
            self.verify_jwk_endorsement(key)?;
            return Ok(key);
        }

        if self.trusted_jwk_sets.keys.is_empty() {
            bail!("Cannot verify token since trusted JWK Set is empty");
        };

        let kid = header
            .kid
            .as_ref()
            .ok_or(anyhow!("Failed to decode kid in the token header"))?;

        let key = &self
            .trusted_jwk_sets
            .find(kid)
            .ok_or(anyhow!("Failed to find Jwk with kid {kid} in JwkSet"))?;

        Ok(key)
    }

    pub async fn verify(&self, token: String) -> anyhow::Result<Value> {
        let header = decode_header(&token).context("Failed to decode attestation token header")?;

        let key = self.get_verification_jwk(&header)?;
        let key_alg = key
            .common
            .key_algorithm
            .ok_or(anyhow!("Failed to find key_algorithm in Jwk"))?
            .to_string();

        let alg = Algorithm::from_str(key_alg.as_str())?;

        let dkey = DecodingKey::from_jwk(key)?;
        let token_data = decode::<Value>(&token, &dkey, &Validation::new(alg))
            .context("Failed to decode attestation token")?;

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use crate::token::jwk::get_jwks_from_file_or_url;
    use rstest::rstest;

    #[rstest]
    #[case("https://", true)]
    #[case("http://example.com", true)]
    #[case("file:///does/not/exist/keys.jwks", true)]
    #[case("/does/not/exist/keys.jwks", true)]
    #[tokio::test]
    async fn test_source_path_validation(#[case] source_path: &str, #[case] expect_error: bool) {
        assert_eq!(
            expect_error,
            get_jwks_from_file_or_url(source_path).await.is_err()
        )
    }

    #[rstest]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"HS256\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        false
    )]
    #[case(
        "{\"keys\":[{\"kty\":\"oct\",\"alg\":\"COCO42\",\"kid\":\"coco123\",\"k\":\"foobar\"}]}",
        true
    )]
    #[tokio::test]
    async fn test_source_reads(#[case] json: &str, #[case] expect_error: bool) {
        let tmp_dir = tempfile::tempdir().expect("to get tmpdir");
        let jwks_file = tmp_dir.path().join("test.jwks");

        let _ = std::fs::write(&jwks_file, json).expect("to get testdata written to tmpdir");

        let p = "file://".to_owned() + jwks_file.to_str().expect("to get path as str");

        assert_eq!(expect_error, get_jwks_from_file_or_url(&p).await.is_err())
    }
}
