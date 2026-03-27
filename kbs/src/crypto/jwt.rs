// Copyright (c) 2026 by The Trustee Authors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Header, Validation};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    nid::Nid,
    pkey::PKey,
    rsa::Rsa,
    stack::Stack,
    x509::{store::X509StoreBuilder, X509StoreContext, X509},
};
use reqwest::Url;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::fs;
use std::str::FromStr;

use crate::crypto::jwk::read_jwk_from_uri;

fn path_to_file_uri(path: &str) -> Result<String> {
    let abs = std::path::Path::new(path)
        .canonicalize()
        .context(format!("invalid local path {path}"))?;
    let abs = abs
        .to_str()
        .context(format!("invalid UTF-8 local path {path}"))?;
    Ok(format!("file://{abs}"))
}

fn normalize_jwk_set_source(source: &str) -> Result<String> {
    if source.starts_with("https://")
        || source.starts_with("http://")
        || source.starts_with("file://")
    {
        return Ok(source.to_string());
    }

    if source.contains("://") {
        bail!("unsupported scheme in {source}");
    }

    path_to_file_uri(source)
}

/// Read a PEM public key from a URI.
///
/// # Arguments
///
/// * `uri` - The URI of the PEM public key.
/// * `allow_insecure_http` - Whether to allow HTTP address as uri.
pub(crate) async fn read_pem_public_key_from_uri(
    uri: &str,
    allow_insecure_http: bool,
) -> Result<DecodingKey> {
    let maybe_url = Url::parse(uri);
    let data = if let Ok(url) = maybe_url {
        match url.scheme() {
            "https" => reqwest::get(uri).await?.bytes().await?.to_vec(),
            "http" if allow_insecure_http => reqwest::get(uri).await?.bytes().await?.to_vec(),
            "file" => std::fs::read(url.path())?,
            _ => {
                bail!("unsupported scheme in {uri}");
            }
        }
    } else {
        std::fs::read(uri)?
    };
    decoding_key_from_public_key_pem(&data).context("failed to decode PEM public key")
}

pub(crate) fn decoding_key_from_public_key_pem(
    public_key_pem: &[u8],
) -> jsonwebtoken::errors::Result<DecodingKey> {
    // Try EC, then RSA, then EdDSA for compatibility with existing behavior.
    if let Ok(key) = DecodingKey::from_ec_pem(public_key_pem) {
        Ok(key)
    } else if let Ok(key) = DecodingKey::from_rsa_pem(public_key_pem) {
        Ok(key)
    } else {
        DecodingKey::from_ed_pem(public_key_pem)
    }
}

pub(crate) fn decode_token_claims<T: DeserializeOwned>(
    token: &str,
    decoding_key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<T> {
    let mut validation = Validation::new(algorithm);
    validation.validate_aud = false;
    let token_data = decode::<T>(token, decoding_key, &validation)?;
    Ok(token_data.claims)
}

pub(crate) fn decode_token_claims_with_any_key<T: DeserializeOwned>(
    token: &str,
    decoding_keys: &[DecodingKey],
) -> Result<T> {
    let header = decode_header(token)?;
    for decoding_key in decoding_keys {
        if let Ok(claims) = decode_token_claims::<T>(token, decoding_key, header.alg) {
            return Ok(claims);
        }
    }
    Err(anyhow!("Cannot verify token with any provided key"))
}

#[derive(Clone)]
pub struct JwtVerifier {
    trusted_jwk_sets: JwkSet,
    trusted_certs: Vec<X509>,
    trusted_pem_public_keys: Vec<DecodingKey>,

    /// The original JWT would bring a verification key inside the header.
    /// If this is true, the verification key is not validated and directly used to verify the token.
    /// This should only be set to true for testing.
    /// While the token signature is still validated, the provenance of the
    /// signing key is not checked and the key could be replaced.
    ///
    /// When false, the key must be endorsed by the certificates or JWK sets
    /// specified above.
    insecure_public_key_from_jwt: bool,
}

impl JwtVerifier {
    /// Create a new JwtVerifier.
    ///
    /// # Arguments
    ///
    /// * `trusted_jwk_set_uris` - The URIs of the trusted JWK sets.
    /// * `trusted_cert_paths` - The paths of the trusted certificates.
    /// * `trusted_pem_public_key_uris` - The URIs of the trusted PEM public keys.
    /// * `insecure_public_key_from_jwt` - Whether to verify the endorsement of the public key from JWT header.
    /// * `insecure_public_key_from_uri` - Whether to allow insecure HTTP address in trusted_pem_public_key_uris.
    pub async fn new(
        trusted_jwk_set_uris: &[String],
        trusted_cert_paths: &[String],
        trusted_pem_public_key_uris: &[String],
        insecure_public_key_from_jwt: bool,
        insecure_public_key_from_uri: bool,
    ) -> Result<Self> {
        let mut trusted_jwk_sets = JwkSet { keys: Vec::new() };
        for uri in trusted_jwk_set_uris {
            let uri = normalize_jwk_set_source(&uri[..])?;
            let mut jwk_set = read_jwk_from_uri(&uri[..], insecure_public_key_from_uri).await?;
            trusted_jwk_sets.keys.append(&mut jwk_set.keys);
        }

        let mut trusted_certs = Vec::new();
        for path in trusted_cert_paths {
            let cert_content =
                fs::read(path).context(format!("failed to read certificate {path}"))?;
            let cert = X509::from_pem(&cert_content)?;
            trusted_certs.push(cert);
        }

        let mut trusted_pem_public_keys = Vec::new();
        for uri in trusted_pem_public_key_uris {
            let public_key =
                read_pem_public_key_from_uri(uri, insecure_public_key_from_uri).await?;
            trusted_pem_public_keys.push(public_key);
        }

        if trusted_jwk_sets.keys.is_empty()
            && trusted_pem_public_keys.is_empty()
            && trusted_certs.is_empty()
            && !insecure_public_key_from_jwt
        {
            bail!("Cannot verify token since no trusted verification materials are provided. \
                Please provide at least one of trusted JWK sets, trusted PEM public keys, or trusted certificates.");
        }

        Ok(Self {
            trusted_jwk_sets,
            trusted_certs,
            trusted_pem_public_keys,
            insecure_public_key_from_jwt,
        })
    }

    fn verify_jwk_endorsement(&self, key: &Jwk) -> Result<()> {
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

        let mut ctx = X509StoreContext::new()?;
        if !ctx.init(&trust_store, &leaf_cert, &cert_chain, |c| c.verify_cert())? {
            bail!("JWK cannot be validated by trust anchor");
        }

        Ok(())
    }

    fn get_verification_jwk<'a>(&'a self, header: &'a Header) -> Result<&'a Jwk> {
        if let Some(key) = &header.jwk {
            if self.insecure_public_key_from_jwt {
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

        self.trusted_jwk_sets
            .find(kid)
            .ok_or(anyhow!("Failed to find Jwk with kid {kid} in JwkSet"))
    }

    pub fn verify(&self, token: &str) -> Result<Value> {
        let header = decode_header(token).context("Failed to decode token header")?;
        if let Ok(key) = self.get_verification_jwk(&header) {
            let key_alg = key
                .common
                .key_algorithm
                .ok_or(anyhow!("Failed to find key_algorithm in Jwk"))?
                .to_string();
            let alg = Algorithm::from_str(key_alg.as_str())?;
            let dkey = DecodingKey::from_jwk(key)?;

            return decode_token_claims::<Value>(token, &dkey, alg)
                .context("Failed to decode token");
        }

        if !self.trusted_pem_public_keys.is_empty() {
            return decode_token_claims_with_any_key::<Value>(token, &self.trusted_pem_public_keys)
                .context("Failed to decode token with trusted PEM public keys");
        }

        Err(anyhow!(
            "Cannot verify token: neither trusted jwk set nor trusted pem public key works"
        ))
    }
}
