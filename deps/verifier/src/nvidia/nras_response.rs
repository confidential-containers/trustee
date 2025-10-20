// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::str::FromStr;

use super::TeeEvidenceParsedClaim;
use crate::nvidia::NrasJwks;

// Internal struct for deserializing the NRAS Payload
#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
struct NrasResponseInternal {
    jwt: Vec<String>,
    eat: HashMap<String, String>,
}

pub struct NrasResponse {
    jwt: String,
    eat: String,
}

impl FromStr for NrasResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let response: NrasResponseInternal = serde_json::from_str(s)?;

        if response.jwt.len() != 2 {
            bail!("Unexpected Payload Format");
        };
        let jwt = response.jwt[1].clone();

        // For now, there should only be one EAT.
        if response.eat.len() != 1 {
            bail!("Unexpected submod count.");
        };

        let eat = response
            .eat
            .values()
            .next()
            .ok_or_else(|| anyhow!("Could not find EAT"))?
            .to_string();

        Ok(NrasResponse { jwt, eat })
    }
}

impl NrasResponse {
    /// Validates JWT and EAT using the provided JWKs
    pub fn validate(&self, jwks: &NrasJwks) -> Result<()> {
        validate_jwt(self.jwt.clone(), jwks)?;
        validate_jwt(self.eat.clone(), jwks)?;

        Ok(())
    }

    /// Extracts TCB Claims from EAT
    /// These claims will not be validated unless
    /// the validate method is called.
    ///
    /// For now, provide all the claims from verifier
    /// usings their original names. This may be refined
    /// in the future.
    pub fn claims(&self) -> Result<TeeEvidenceParsedClaim> {
        let mut claims = get_jwt_payload(self.eat.clone())?;
        let jwt_claims = get_jwt_payload(self.jwt.clone())?;

        // If there is an overall attestation result in the JWT,
        // add it to the claims.
        if let Some(overall_result) = jwt_claims.pointer("/x-nvidia-overall-att-result") {
            let claims_dict = claims
                .as_object_mut()
                .ok_or_else(|| anyhow!("Unexpected claims format."))?;
            claims_dict.insert(
                "x-nvidia-overall-att-result".to_string(),
                overall_result.clone(),
            );
        }
        Ok(claims)
    }
}

pub fn get_jwt_payload(jwt: String) -> Result<serde_json::Value> {
    let parts: Vec<&str> = jwt.split('.').collect();

    if parts.len() != 3 {
        bail!("Malformed JWT");
    }

    let b64_engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    let payload_bytes = b64_engine.decode(parts[1])?;
    let payload_str = String::from_utf8_lossy(&payload_bytes);

    Ok(serde_json::from_str(&payload_str)?)
}

pub fn get_jwt_kid(jwt: String) -> Result<String> {
    let header = jsonwebtoken::decode_header(&jwt)?;
    let kid = header.kid.ok_or_else(|| anyhow!("Could not find KID"))?;

    Ok(kid)
}

pub fn validate_jwt(jwt: String, jwks: &NrasJwks) -> Result<()> {
    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        exp: usize,
        iat: usize,
        iss: String,
        nbf: usize,
    }

    let kid = get_jwt_kid(jwt.clone())?;
    let jwk = jwks
        .get(kid)
        .ok_or_else(|| anyhow!("Could not find KID in JWKs"))?;

    let decoding_key = DecodingKey::from_jwk(&jwk)?;

    decode::<Claims>(&jwt, &decoding_key, &Validation::new(Algorithm::ES384))?;

    Ok(())
}
