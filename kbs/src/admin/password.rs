// Copyright (c) 2025 by NVIDIA.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use jwt_simple::{
    claims::NoCustomClaims,
    common::VerificationOptions,
    prelude::{Claims, Ed25519KeyPair, EdDSAKeyPairLike, EdDSAPublicKeyLike},
};
use log::info;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

use crate::admin::error::*;
use crate::admin::AdminBackend;

const ADMIN_TOKEN_ISSUER: &str = "Trustee Admin";

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
#[serde(default)]
pub struct PasswordAdminConfig {
    pub personas: Vec<PasswordPersona>,
    /// The number of hours that an admin token will be valid for.
    /// After the token expires, an admin must login again and receive
    /// a new token.
    /// The token timing checks are accurate to within 15 minutes.
    #[serde(default = "default_token_hours")]
    pub admin_token_life_hours: u64,
    /// The key pair used for signing and validating the admin tokens.
    /// If a path is provided, the key pair will be loaded from a file.
    /// This be used to share auth tokens between Trustee instances and
    /// to allow Trustee to restart with invalidating existing tokens.
    /// The key pair should be in PEM format.
    /// If no path is provided, a random key pair will be generated.
    pub key_pair_path: Option<PathBuf>,
}

fn default_token_hours() -> u64 {
    24
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq)]
pub struct PasswordPersona {
    pub username: String,
    /// An argon2 pch, which includes a salt.
    pub password_hash: String,
}

pub struct PasswordAdminBackend {
    personas: HashMap<String, PasswordPersona>,
    admin_token_life_hours: u64,
    key_pair: Ed25519KeyPair,
}

impl PasswordAdminBackend {
    pub fn new(config: PasswordAdminConfig) -> Result<Self> {
        let mut personas = HashMap::new();
        for p in config.personas {
            personas.insert(p.username.clone(), p.clone());
        }

        // If no personas are specified, create one admin persona
        // with a random password.
        // Print the password to the log.
        if personas.is_empty() {
            let password: String = thread_rng()
                .sample_iter(&Alphanumeric)
                .take(14)
                .map(char::from)
                .collect();

            info!("No admin personas provided for the password admin backend. Creating `default_admin` persona with password: {}", &password);

            let salt = SaltString::generate(&mut OsRng);
            let argon2 = Argon2::default();
            let password_hash = argon2
                .hash_password(password.as_bytes(), &salt)
                .map_err(|_| Error::InvalidHash)?
                .to_string();

            personas.insert(
                "default_admin".to_string(),
                PasswordPersona {
                    username: "default_admin".to_string(),
                    password_hash,
                },
            );
        }

        // TODO read key pair from file
        let key_pair = Ed25519KeyPair::generate();

        Ok(PasswordAdminBackend {
            personas,
            admin_token_life_hours: config.admin_token_life_hours,
            key_pair,
        })
    }
}

impl AdminBackend for PasswordAdminBackend {
    fn validate_admin_token(&self, request: &HttpRequest) -> Result<()> {
        let bearer = Authorization::<Bearer>::parse(request)?.into_scheme();
        let token = bearer.token();

        // The default time tolerance is 15 minutes.
        // Reduce this to 3 minutes.
        let options = VerificationOptions {
            time_tolerance: Some(std::time::Duration::from_secs(180).into()),
            ..Default::default()
        };

        let res = self
            .key_pair
            .public_key()
            .verify_token::<NoCustomClaims>(token, Some(options));

        match res {
            Ok(claims) => {
                let username = claims.subject.ok_or(Error::AdminTokenInvalid)?;
                info!("Admin access granted for {}", username);

                return Ok(());
            }
            Err(e) => {
                info!("Access not granted due to: \n{}", e);

                return Err(Error::AdminAccessDenied);
            }
        }
    }

    fn generate_admin_token(&self, login_data: serde_json::Value) -> Result<String> {
        #[derive(Deserialize)]
        struct LoginData {
            username: String,

            // This admin backend should only be used with HTTPS otherwise this password
            // will be exposed in transit.
            password: String,
        }

        let login_data: LoginData =
            serde_json::from_value(login_data).map_err(|_| Error::ParseAdminLoginFailed)?;

        let persona = self
            .personas
            .get(&login_data.username)
            .ok_or(Error::WrongUsernameOrPassword)?;

        // Check password against password hash.
        let hash = PasswordHash::new(&persona.password_hash).map_err(|_| Error::InvalidHash)?;

        Argon2::default()
            .verify_password(login_data.password.as_bytes(), &hash)
            .map_err(|_| Error::WrongUsernameOrPassword)?;

        info!("Password correct for {}", &login_data.username);

        let claims = Claims::create(
            std::time::Duration::from_secs(self.admin_token_life_hours * 3600).into(),
        )
        .with_subject(login_data.username.to_owned())
        .with_issuer(ADMIN_TOKEN_ISSUER);

        let token = self
            .key_pair
            .sign(claims)
            .map_err(|_| Error::TokenCreationFailed)?;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use actix_web::http::header;
    use actix_web_httpauth::headers::authorization::Authorization;
    use actix_web_httpauth::headers::authorization::Bearer;

    use serde_json::json;

    #[test]
    fn login_and_get_token() {
        let config = PasswordAdminConfig {
            personas: vec![PasswordPersona {
                username: "test1".to_string(),
                password_hash: "$argon2id$v=19$m=16,t=2,p=1$YWJjZGVmZ2g$Y42gC/3sp/gxCZCbZytGYQ"
                    .to_string(),
            }],
            admin_token_life_hours: 1,
            key_pair_path: None,
        };

        let login_data = json!({"username": "test1", "password": "test1"});

        let admin_backend = PasswordAdminBackend::new(config).unwrap();
        let token = admin_backend.generate_admin_token(login_data).unwrap();

        let auth = Authorization::from(Bearer::new(token));
        let req = actix_web::test::TestRequest::default()
            .insert_header((header::AUTHORIZATION, auth.to_string()))
            .to_http_request();

        admin_backend.validate_admin_token(&req).unwrap();
    }
}
