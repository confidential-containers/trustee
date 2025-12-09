// Copyright (c) 2025 IBM and Red Hat.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

//! This module provides plugin support for the cryptographic backend.
//!
//! For more information about PKCS_11 and the methodologies used, see the following
//! * [PKCS_11 Usage Guide](<https://docs.oasis-open.org/pkcs11/pkcs11-ug/v3.2/pkcs11-ug-v3.2.html>)
//! * [PKCS_11 Specification v3.0](<https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.2/pkcs11-spec-v3.2.html>)
//! * [PKCS_11 Base Specification v3.0](<https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/os/pkcs11-base-v3.0-os.html>)
use crate::plugins::resource::{ResourceDesc, StorageBackend};
use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    mechanism::{
        rsa::{PkcsMgfType, PkcsOaepParams, PkcsOaepSource},
        Mechanism, MechanismType,
    },
    object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};
use educe::Educe;
use serde::Deserialize;
use std::{collections::HashMap, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

use super::super::plugin_manager::ClientPlugin;

/// Enum representing supported RSA mechanisms.
#[derive(Educe, Deserialize, Clone, PartialEq, Default)]
#[educe(Debug)]
pub enum RsaMechanism {
    /// RSA mechanism using PKCS#1 OAEP MGF1_SHA256 padding. Recommended for secure production use.
    #[default]
    RsaPkcsOaep,
    /// RSA mechanism using PKCS#1 v1.5 with MGF1_SHA1 padding.
    ///
    /// ⚠️ This mechanism relies on SHA-1, which is considered deprecated and insecure.
    /// It should only be used for testing or legacy compatibility purposes.    
    RsaPkcsTest,
}

impl RsaMechanism {
    /// Converts the enum variant into a corresponding PKCS#11 mechanism.
    pub fn to_pkcs11_mechanism(&self) -> Mechanism {
        match self {
            RsaMechanism::RsaPkcsOaep => Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                MechanismType::SHA256,
                PkcsMgfType::MGF1_SHA256,
                PkcsOaepSource::empty(),
            )),
            RsaMechanism::RsaPkcsTest => Mechanism::RsaPkcsOaep(PkcsOaepParams::new(
                MechanismType::SHA1,
                PkcsMgfType::MGF1_SHA1,
                PkcsOaepSource::empty(),
            )),
        }
    }
}

#[derive(Educe, Deserialize, Clone, PartialEq)]
#[educe(Debug)]
pub struct Pkcs11Config {
    /// Path to the PKCS11 module.
    module: PathBuf,

    /// The index of the slot to be used. If not provided, the first slot will be used.
    #[serde(default)]
    slot_index: u8,

    /// The user pin for authenticating the session.
    #[educe(Debug(ignore))]
    pin: String,

    /// RSA mechanism to use.
    #[serde(default)]
    rsa_mechanism: RsaMechanism,

    /// String used to lookup private or public key for cryptographic operations
    #[serde(default)]
    lookup_label: String,
}

pub struct Pkcs11Backend {
    session: Arc<Mutex<Session>>,
    lookup_label: String,
    rsa_mechanism: Arc<RsaMechanism>,
}

impl TryFrom<Pkcs11Config> for Pkcs11Backend {
    type Error = anyhow::Error;

    fn try_from(config: Pkcs11Config) -> anyhow::Result<Self> {
        let rsa_mechanism = Arc::new(config.rsa_mechanism);
        let pkcs11 = Pkcs11::new(config.module).context("unable to open pkcs11 module")?;
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

        let slots = pkcs11.get_slots_with_token()?;
        let slot_index = usize::from(config.slot_index);
        if slot_index >= slots.len() {
            bail!("Slot index out of range");
        }

        let session = pkcs11.open_rw_session(slots[slot_index])?;
        session.login(UserType::User, Some(&AuthPin::new(config.pin.clone())))?;

        let lookup_label = config.lookup_label;
        Ok(Self {
            session: Arc::new(Mutex::new(session)),
            rsa_mechanism: rsa_mechanism.clone(),
            lookup_label,
        })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for Pkcs11Backend {
    async fn handle(
        &self,
        body: &[u8],
        _query: &HashMap<String, String>,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let desc = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with '/'")?;

        match desc {
            "wrap-key" => self.wrap_key_handle(body, method).await,
            _ => {
                let (action, params) = desc.split_once('/').context("accessed path is invalid")?;
                match action {
                    "resource" => self.resource_handle(params, body, method).await,
                    _ => bail!("invalid path"),
                }
            }
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &str,
        method: &Method,
    ) -> Result<bool> {
        match *method {
            Method::GET => Ok(false),
            Method::POST => Ok(true),
            _ => bail!("invalid method"),
        }
    }

    async fn encrypted(
        &self,
        _body: &[u8],
        _query: &HashMap<String, String>,
        _path: &str,
        _method: &Method,
    ) -> Result<bool> {
        Ok(true)
    }
}

#[async_trait::async_trait]
impl StorageBackend for Pkcs11Backend {
    async fn read_secret_resource(&self, resource_desc: ResourceDesc) -> Result<Vec<u8>> {
        let session = self.session.lock().await;

        // find object with matching label
        let attributes = vec![Attribute::Label(Vec::from(resource_desc.to_string()))];
        let objects = session.find_objects(&attributes)?;

        if objects.is_empty() {
            bail!("Could not find object with label {}", resource_desc);
        }
        let object = objects[0];

        // check that object has a readable value attribute
        let value_attribute = vec![AttributeType::Value];
        let attribute_map = session.get_attribute_info_map(object, &value_attribute)?;
        let Some(AttributeInfo::Available(_size)) = attribute_map.get(&AttributeType::Value) else {
            bail!("Key does not have value attribute available.");
        };

        // get the value
        let value = &session
            .get_attributes(object, &value_attribute)
            .context("unable to fetch attributes")?;

        let value = value.first().ok_or(anyhow!("empty attributes returned"))?;

        let Attribute::Value(resource_bytes) = value else {
            bail!("Failed to get value.");
        };

        Ok(resource_bytes.clone())
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let attributes = vec![
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::Extractable(true),
            Attribute::Private(true),
            Attribute::Value(data.to_vec()),
            Attribute::Label(Vec::from(resource_desc.to_string())),
        ];

        let _object = self.session.lock().await.create_object(&attributes)?;

        Ok(())
    }
}

impl Pkcs11Backend {
    async fn resource_handle(&self, tag: &str, body: &[u8], method: &Method) -> Result<Vec<u8>> {
        let tag = ResourceDesc::try_from(tag).context("invalid path")?;

        match *method {
            Method::GET => self.read_secret_resource(tag).await,
            Method::POST => {
                self.write_secret_resource(tag, body).await?;
                Ok(vec![])
            }
            _ => bail!("Illegal HTTP method. Only supports `GET` and `POST`"),
        }
    }

    async fn wrap_key_handle(&self, body: &[u8], method: &Method) -> Result<Vec<u8>> {
        match *method {
            Method::POST => self.wrapkey_wrap(body).await,
            Method::GET => self.wrapkey_unwrap(body).await,
            _ => bail!("invalid method"),
        }
    }

    async fn wrapkey_wrap(&self, body: &[u8]) -> Result<Vec<u8>> {
        let pubkey_template = vec![
            Attribute::Label(self.lookup_label.clone().into()),
            Attribute::Class(ObjectClass::PUBLIC_KEY),
        ];

        let mut pubkey = self
            .session
            .lock()
            .await
            .find_objects(&pubkey_template)
            .context("unable to find public wrap key in PKCS11 module")?;

        let encrypted = self
            .session
            .lock()
            .await
            .encrypt(
                &self.rsa_mechanism.to_pkcs11_mechanism(),
                pubkey.remove(0),
                body,
            )
            .context("unable to encrypt HTTP body with public wrap key")?;

        Ok(encrypted)
    }

    async fn wrapkey_unwrap(&self, body: &[u8]) -> Result<Vec<u8>> {
        let privkey_template = vec![
            Attribute::Label(self.lookup_label.clone().into()),
            Attribute::Class(ObjectClass::PRIVATE_KEY),
        ];

        let mut privkey = self
            .session
            .lock()
            .await
            .find_objects(&privkey_template)
            .context("unable to find private wrap key in PKCS11 module")?;
        let decrypted = self
            .session
            .lock()
            .await
            .decrypt(
                &self.rsa_mechanism.to_pkcs11_mechanism(),
                privkey.remove(0),
                body,
            )
            .context("unable to decrypt HTTP body with private wrap key")?;

        Ok(decrypted)
    }
}
/// In general tests using softhsm has to run in a serial scope as they are session locked
#[cfg(test)]
mod tests {
    use crate::plugins::{
        pkcs11::{
            Pkcs11Backend, Pkcs11Config,
            RsaMechanism::{RsaPkcsOaep, RsaPkcsTest},
        },
        resource::backend::{ResourceDesc, StorageBackend},
    };
    use serial_test::serial;
    use std::process::Command;

    static LOOKUP_LABEL: &'static str = "trustee-test";
    static HSM_USER_PIN: &'static str = "12345678";
    static SOFTHSM_PATH: &'static str = "/usr/lib/softhsm/libsofthsm2.so";

    async fn before_test() {
        let status = Command::new("bash")
            .arg("test/script/plugin/pkcs11/".to_owned() + "generate_keypair_with_label.sh")
            .arg(LOOKUP_LABEL)
            .arg(HSM_USER_PIN)
            .arg(SOFTHSM_PATH)
            .status()
            .expect("failed to run setup script");
        assert!(status.success(), "setup script failed");
    }
    struct Teardown;
    impl Drop for Teardown {
        fn drop(&mut self) {
            // This will run even if the test panics
            let status = std::process::Command::new("bash")
                .arg("test/script/plugin/pkcs11/delete_by_label.sh")
                .arg(LOOKUP_LABEL)
                .arg(HSM_USER_PIN)
                .arg(SOFTHSM_PATH)
                .status()
                .expect("failed to run teardown script");
            assert!(status.success(), "teardown script failed");
        }
    }

    const TEST_DATA: &[u8] = b"testdata";

    // This will only work if SoftHSM is setup accordingly.
    #[tokio::test]
    #[serial]
    async fn write_and_read_resource() {
        let config = Pkcs11Config {
            module: SOFTHSM_PATH.into(),
            slot_index: 0,
            // This pin must be set for SoftHSM
            pin: HSM_USER_PIN.to_string(),
            rsa_mechanism: RsaPkcsTest,
            lookup_label: "".into(),
        };

        let backend = Pkcs11Backend::try_from(config).unwrap();

        let resource_desc = ResourceDesc {
            repository_name: "default".into(),
            resource_type: "test".into(),
            resource_tag: "test".into(),
        };

        backend
            .write_secret_resource(resource_desc.clone(), TEST_DATA)
            .await
            .expect("write secret resource failed");
        let data = backend
            .read_secret_resource(resource_desc)
            .await
            .expect("read secret resource failed");

        assert_eq!(&data[..], TEST_DATA);
    }

    // This will only work is SoftHsm is setup accordingly.
    #[tokio::test]
    #[serial]
    async fn wrap_and_unwrap_data() {
        before_test().await;
        let _teardown = Teardown;
        let config = Pkcs11Config {
            module: SOFTHSM_PATH.into(),
            slot_index: 0,
            // This pin must be set for SoftHSM
            pin: HSM_USER_PIN.to_string(),
            rsa_mechanism: RsaPkcsTest,
            lookup_label: LOOKUP_LABEL.to_string(),
        };

        let backend = Pkcs11Backend::try_from(config).unwrap();

        let data = "TEST";

        let wrapped = backend.wrapkey_wrap(data.as_bytes()).await.unwrap();

        assert_ne!(data.as_bytes(), wrapped);

        let unwrapped = backend.wrapkey_unwrap(&wrapped).await.unwrap();

        assert_eq!(data.as_bytes(), unwrapped);
    }
    #[tokio::test]
    #[should_panic(expected = "PKCS11 error")]
    #[serial]
    async fn expected_failure_using_softhsm_mfg_sha256() {
        before_test().await;
        let _teardown = Teardown;

        let config = Pkcs11Config {
            module: SOFTHSM_PATH.into(),
            slot_index: 0,
            // This pin must be set for SoftHSM
            pin: HSM_USER_PIN.to_string(),
            rsa_mechanism: RsaPkcsOaep,
            lookup_label: LOOKUP_LABEL.to_string(),
        };
        let backend = Pkcs11Backend::try_from(config).unwrap();

        let data = "TEST";

        let _wrapped = backend.wrapkey_wrap(data.as_bytes()).await.unwrap();
    }
}
