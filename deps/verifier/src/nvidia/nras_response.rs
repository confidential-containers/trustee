// Copyright (c) 2025 NVIDIA
//
// SPDX-License-Identifier: Apache-2.0
//

use anyhow::{Result, anyhow, bail};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use super::TeeEvidenceParsedClaim;
use super::eat::DetachedEat;
use crate::nvidia::NrasJwks;

/// Formatted Nras Response
pub struct NrasResponse {
    eat: DetachedEat,
}

impl FromStr for NrasResponse {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let eat = DetachedEat::from_str(s)?;

        // For now, there should only be one EAT.
        if eat.device_jwts().len() != 1 {
            bail!("Unexpected submod count.");
        };

        Ok(NrasResponse { eat })
    }
}

impl NrasResponse {
    /// Validates JWT and EAT using the provided JWKs
    pub fn validate(&self, jwks: &NrasJwks) -> Result<()> {
        validate_jwt(self.eat.overall_jwt().to_string(), jwks)?;
        for jwt in self.eat.device_jwts() {
            validate_jwt(jwt.clone(), jwks)?;
        }

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
        self.eat
            .claims()?
            .pop()
            .ok_or_else(|| anyhow!("Could not find EAT"))
    }
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
