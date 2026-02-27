// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use log::info;
use serde::Deserialize;
use std::path::PathBuf;

use crate::admin::error::*;
use crate::admin::AdminBackend;

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct SimpleAdminConfig {
    pub personas: Vec<SimplePersonaConfig>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct SimplePersonaConfig {
    pub id: String,
    pub public_key_path: PathBuf,
}

pub struct SimpleAdminBackend {
    personas: Vec<SimplePersona>,
}

pub struct SimplePersona {
    id: String,
    public_key: DecodingKey,
}

impl SimpleAdminBackend {
    pub fn new(config: SimpleAdminConfig) -> Result<Self> {
        let mut personas = Vec::new();

        for persona_config in &config.personas {
            let user_public_key_pem = std::fs::read_to_string(&persona_config.public_key_path)?;
            let public_key = DecodingKey::from_ed_pem(user_public_key_pem.as_bytes())?;

            personas.push(SimplePersona {
                id: persona_config.id.clone(),
                public_key,
            });
        }

        Ok(SimpleAdminBackend { personas })
    }
}

impl AdminBackend for SimpleAdminBackend {
    fn validate_admin_token(&self, request: &HttpRequest) -> Result<String> {
        let bearer = Authorization::<Bearer>::parse(request)?.into_scheme();
        let token = bearer.token();

        for persona in &self.personas {
            let validation = Validation::new(Algorithm::EdDSA);
            let res = decode::<serde_json::Value>(token, &persona.public_key, &validation);
            match res {
                Ok(_claims) => {
                    info!("Admin token validated (simple) for persona: {}", persona.id);

                    // Return the first matching persona
                    return Ok(persona.id.clone());
                }
                Err(e) => {
                    info!(
                        "Admin token not validated for {} due to: \n{}",
                        persona.id, e
                    );
                }
            }
        }

        Err(Error::AdminAccessDenied)
    }
}
