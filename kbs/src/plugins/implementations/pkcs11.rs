// Copyright (c) 2025 IBM and Red Hat.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use crate::plugins::resource::{ResourceDesc, StorageBackend};
use actix_web::http::Method;
use anyhow::{anyhow, bail, Context, Result};
use cryptoki::{
    context::{CInitializeArgs, Pkcs11},
    object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass},
    session::{Session, UserType},
    types::AuthPin,
};
use derivative::Derivative;
use serde::Deserialize;
use std::{path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

use super::super::plugin_manager::ClientPlugin;

#[derive(Derivative, Deserialize, Clone, PartialEq)]
#[derivative(Debug)]
pub struct Pkcs11Config {
    /// Path to the PKCS11 module.
    module: PathBuf,

    /// The index of the slot to be used. If not provided, the first slot will be used.
    #[serde(default)]
    slot_index: u8,

    /// The user pin for authenticating the session.
    #[derivative(Debug = "ignore")]
    pin: String,
}

pub struct Pkcs11Backend {
    session: Arc<Mutex<Session>>,
}

impl TryFrom<Pkcs11Config> for Pkcs11Backend {
    type Error = anyhow::Error;

    fn try_from(config: Pkcs11Config) -> anyhow::Result<Self> {
        let pkcs11 = Pkcs11::new(config.module).context("unable to open pkcs11 module")?;
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

        let slots = pkcs11.get_slots_with_token()?;
        let slot_index = usize::from(config.slot_index);
        if slot_index >= slots.len() {
            bail!("Slot index out of range");
        }

        let session = pkcs11.open_rw_session(slots[slot_index])?;
        session.login(UserType::User, Some(&AuthPin::new(config.pin.clone())))?;

        Ok(Self {
            session: Arc::new(Mutex::new(session)),
        })
    }
}

#[async_trait::async_trait]
impl ClientPlugin for Pkcs11Backend {
    async fn handle(
        &self,
        body: &[u8],
        _query: &str,
        path: &str,
        method: &Method,
    ) -> Result<Vec<u8>> {
        let desc = path
            .strip_prefix('/')
            .context("accessed path is illegal, should start with '/'")?;

        let (action, params) = desc.split_once('/').context("accessed path is invalid")?;
        match action {
            "resource" => self.resource_handle(params, body, method).await,
            _ => bail!("invalid path"),
        }
    }

    async fn validate_auth(
        &self,
        _body: &[u8],
        _query: &str,
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
        _query: &str,
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
            bail!(
                "Could not find object with label {}",
                resource_desc.to_string()
            );
        }
        let object = objects[0];

        // check that object has a readable value attribute
        let value_attribute = vec![AttributeType::Value];
        let attribute_map = session.get_attribute_info_map(object, value_attribute.clone())?;
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
}

#[cfg(test)]
mod tests {
    use crate::plugins::{
        pkcs11::{Pkcs11Backend, Pkcs11Config},
        resource::backend::{ResourceDesc, StorageBackend},
    };

    const TEST_DATA: &[u8] = b"testdata";

    // This will only work if SoftHSM is setup accordingly.
    #[ignore]
    #[tokio::test]
    async fn write_and_read_resource() {
        let config = Pkcs11Config {
            module: "/usr/lib64/pkcs11/libsofthsm2.so".into(),
            slot_index: Some(1),
            // This pin must be set for SoftHSM
            pin: "test".to_string(),
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
}
