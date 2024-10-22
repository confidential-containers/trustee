// Copyright (c) 2024 by IBM.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Result};
use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::object::{Attribute, AttributeInfo, AttributeType, KeyType, ObjectClass};
use cryptoki::session::{Session, UserType};
use cryptoki::types::AuthPin;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Mutex;

use super::backend::{ResourceDesc, StorageBackend};

#[derive(Debug, Deserialize, Clone, PartialEq)]
pub struct Pkcs11Config {
    /// Path to the Pkcs11 module
    module: String,

    /// The index of the slot to be used
    /// If not provided, the first slot will be used.
    slot_index: Option<u8>,

    /// The user pin for authenticating the session
    pin: String,
}

pub struct Pkcs11Backend {
    session: Arc<Mutex<Session>>,
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
        let value = &session.get_attributes(object, &value_attribute)?[0];
        let Attribute::Value(resource_bytes) = value else {
            bail!("Failed to get value.");
        };

        Ok(resource_bytes.clone())
    }

    async fn write_secret_resource(&self, resource_desc: ResourceDesc, data: &[u8]) -> Result<()> {
        let mut attributes = vec![];
        attributes.push(Attribute::Class(ObjectClass::SECRET_KEY));
        attributes.push(Attribute::KeyType(KeyType::GENERIC_SECRET));
        attributes.push(Attribute::Extractable(true));
        attributes.push(Attribute::Private(true));

        attributes.push(Attribute::Value(data.to_vec()));
        attributes.push(Attribute::Label(Vec::from(resource_desc.to_string())));

        let _object = self.session.lock().await.create_object(&attributes)?;

        Ok(())
    }
}

impl Pkcs11Backend {
    pub fn new(config: &Pkcs11Config) -> Result<Self> {
        // setup global context
        let pkcs11 = Pkcs11::new(config.module.clone())?;
        pkcs11.initialize(CInitializeArgs::OsThreads).unwrap();

        // create session
        let slots = pkcs11.get_slots_with_token()?;
        let slot_index = usize::from(config.slot_index.unwrap_or(0));
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

#[cfg(test)]
mod tests {
    use crate::plugins::resource::{
        backend::{ResourceDesc, StorageBackend},
        pkcs11::{Pkcs11Backend, Pkcs11Config},
    };

    const TEST_DATA: &[u8] = b"testdata";

    // This will only work if SoftHSM is setup
    #[ignore]
    #[tokio::test]
    async fn write_and_read_resource() {
        let config = Pkcs11Config {
            module: "/usr/local/lib/softhsm/libsofthsm2.so".to_string(),
            slot_index: None,
            // This pin must be set for SoftHSM
            pin: "test".to_string(),
        };

        let backend = Pkcs11Backend::new(&config).unwrap();

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
