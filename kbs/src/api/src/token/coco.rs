// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::token::{AttestationTokenVerifier, AttestationTokenVerifierConfig};
use anyhow::*;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::rsa::Rsa;
use openssl::sign::Verifier;
use openssl::stack::Stack;
use openssl::x509::store::{X509Store, X509StoreBuilder};
use openssl::x509::{X509StoreContext, X509};
use serde_json::Value;

pub struct CoCoAttestationTokenVerifier {
    trusted_certs: Option<X509Store>,
}

impl CoCoAttestationTokenVerifier {
    pub fn new(config: &AttestationTokenVerifierConfig) -> Result<Self> {
        let trusted_certs = match &config.trusted_certs_paths {
            Some(paths) => {
                let mut store_builder = X509StoreBuilder::new()?;
                for path in paths {
                    let trust_cert_pem = std::fs::read(path)
                        .map_err(|e| anyhow!("Load trusted certificate failed: {e}"))?;
                    let trust_cert = X509::from_pem(&trust_cert_pem)?;
                    store_builder.add_cert(trust_cert.to_owned())?;
                }
                Some(store_builder.build())
            }
            None => None,
        };

        Ok(Self { trusted_certs })
    }
}

#[async_trait]
impl AttestationTokenVerifier for CoCoAttestationTokenVerifier {
    async fn verify(&self, token: String) -> Result<String> {
        let split_token: Vec<&str> = token.split('.').collect();
        if !split_token.len() == 3 {
            bail!("Illegal JWT format")
        }

        let header = URL_SAFE_NO_PAD.decode(split_token[0])?;
        let claims = URL_SAFE_NO_PAD.decode(split_token[1])?;
        let signature = URL_SAFE_NO_PAD.decode(split_token[2])?;

        let header_value = serde_json::from_slice::<Value>(&header)?;
        let claims_value = serde_json::from_slice::<Value>(&claims)?;

        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let Some(exp) = claims_value["exp"].as_i64() else {
            bail!("token expiration unset");
        };
        if exp < now {
            bail!("token expired");
        }
        if let Some(nbf) = claims_value["nbf"].as_i64() {
            if nbf > now {
                bail!("before validity");
            }
        }

        let jwk_value = claims_value["jwk"].as_object().ok_or_else(|| anyhow!("CoCo Attestation Token Claims must contain public key (JWK format) to verify signature"))?;
        let jwk = serde_json::to_string(&jwk_value)?;
        let rsa_jwk = serde_json::from_str::<RsaJWK>(&jwk)?;
        let payload = format!("{}.{}", &split_token[0], &split_token[1])
            .as_bytes()
            .to_vec();

        match header_value["alg"].as_str() {
            Some("RS384") => {
                if rsa_jwk.alg != *"RS384" {
                    bail!("Unmatched RSA JWK alg");
                }
                rs384_verify(&payload, &signature, &rsa_jwk)?;
            }
            None => {
                bail!("Miss `alg` in JWT header")
            }
            _ => {
                bail!("Unsupported JWT algrithm")
            }
        }

        let Some(trusted_store) = &self.trusted_certs else {
            log::warn!("No Trusted Certificate in Config, skip verification of JWK cert of Attestation Token");
            return Ok(serde_json::to_string(&claims_value)?);
        };

        let mut cert_chain: Vec<X509> = vec![];

        // Get certificate chain from 'x5c' or 'x5u' in JWK.
        if let Some(x5c) = rsa_jwk.x5c {
            for base64_der_cert in x5c {
                let der_cert = URL_SAFE_NO_PAD.decode(base64_der_cert)?;
                let cert = X509::from_der(&der_cert)?;
                cert_chain.push(cert)
            }
        } else if let Some(x5u) = rsa_jwk.x5u {
            download_cert_chain(x5u, &mut cert_chain).await?;
        } else {
            bail!("Missing certificate in Attestation Token JWK");
        }

        // Check certificate is valid and trustworthy
        let mut untrusted_stack = Stack::<X509>::new()?;
        for cert in cert_chain.iter().skip(1) {
            untrusted_stack.push(cert.clone())?;
        }
        let mut context = X509StoreContext::new()?;
        if !context.init(trusted_store, &cert_chain[0], &untrusted_stack, |ctx| {
            ctx.verify_cert()
        })? {
            bail!("Untrusted certificate in Attestation Token JWK");
        };

        // Check the public key in JWK is consistent with the public key in certificate
        let n = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&rsa_jwk.n)?)?;
        let e = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&rsa_jwk.e)?)?;
        let rsa_public_key = Rsa::from_public_components(n, e)?;
        let rsa_pkey = PKey::from_rsa(rsa_public_key)?;
        let cert_pub_key = cert_chain[0].public_key()?;
        if !cert_pub_key.public_eq(&rsa_pkey) {
            bail!("Certificate Public Key Mismatched in Attestation Token");
        }

        Ok(serde_json::to_string(&claims_value)?)
    }
}

#[allow(dead_code)]
#[derive(serde::Deserialize, Clone, Debug)]
struct RsaJWK {
    kty: String,
    alg: String,
    n: String,
    e: String,
    x5u: Option<String>,
    x5c: Option<Vec<String>>,
}

fn rs384_verify(payload: &[u8], signature: &[u8], jwk: &RsaJWK) -> Result<()> {
    let n = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&jwk.n)?)?;
    let e = openssl::bn::BigNum::from_slice(&URL_SAFE_NO_PAD.decode(&jwk.e)?)?;
    let rsa_public_key = Rsa::from_public_components(n, e)?;
    let rsa_pkey = PKey::from_rsa(rsa_public_key)?;

    let mut verifier = Verifier::new(MessageDigest::sha384(), &rsa_pkey)?;
    verifier.update(payload)?;

    if !verifier.verify(signature)? {
        bail!("RS384 verify failed")
    }

    Ok(())
}

async fn download_cert_chain(url: String, mut chain: &mut Vec<X509>) -> Result<()> {
    let res = reqwest::get(url).await?;
    match res.status() {
        reqwest::StatusCode::OK => {
            let pem_cert_chain = res.text().await?;
            parse_pem_cert_chain(pem_cert_chain, &mut chain)?;
        }
        _ => {
            bail!(
                "Request x5u in Attestation Token JWK Failed, Response: {:?}",
                res.text().await?
            );
        }
    }

    Ok(())
}

fn parse_pem_cert_chain(pem_cert_chain: String, chain: &mut Vec<X509>) -> Result<()> {
    for pem in pem_cert_chain.split("-----END CERTIFICATE-----") {
        let trimmed = format!("{}\n-----END CERTIFICATE-----", pem.trim());
        if !trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            continue;
        }
        let cert = X509::from_pem(trimmed.as_bytes())
            .map_err(|_| anyhow!("Invalid PEM certificate chain"))?;
        chain.push(cert);
    }

    Ok(())
}

#[allow(unused_imports)]
mod test {
    use super::*;

    #[test]
    fn test_parse_pem_cert_chain() {
        let pem_cert_chain =
            std::fs::read_to_string("../../test/data/test_cert_chain.pem").unwrap();
        let mut chain: Vec<X509> = Vec::new();
        assert!(parse_pem_cert_chain(pem_cert_chain, &mut chain).is_ok());
        assert_eq!(chain.len(), 2);
    }
}
