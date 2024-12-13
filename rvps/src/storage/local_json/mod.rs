use std::{fs, path::PathBuf};

use super::ReferenceValueStorage;
use crate::ReferenceValue;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::debug;
use serde::Deserialize;
use tokio::sync::RwLock;

const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values.json";

pub struct LocalJson {
    file_path: String,
    lock: RwLock<i32>,
}

fn default_file_path() -> String {
    FILE_PATH.to_string()
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct Config {
    #[serde(default = "default_file_path")]
    pub file_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            file_path: default_file_path(),
        }
    }
}

impl LocalJson {
    pub fn new(config: Config) -> Result<Self> {
        let mut path = PathBuf::new();
        path.push(&config.file_path);

        let parent_dir = path.parent().ok_or_else(|| {
            anyhow!("Illegal `file_path` for LocalJson's config without a parent dir.")
        })?;
        debug!("create path for LocalJson: {:?}", parent_dir);
        fs::create_dir_all(parent_dir)?;
        Ok(Self {
            file_path: config.file_path,
            lock: RwLock::new(0),
        })
    }
}

#[async_trait]
impl ReferenceValueStorage for LocalJson {
    async fn set(&self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.write().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let mut rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let mut res = None;
        if let Some(item) = rvs.iter_mut().find(|it| it.name == name) {
            res = Some(item.to_owned());
            *item = rv;
        } else {
            rvs.push(rv);
        }

        let contents = serde_json::to_vec(&rvs)?;
        tokio::fs::write(&self.file_path, contents).await?;
        Ok(res)
    }

    async fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let rv = rvs.into_iter().find(|rv| rv.name == name);
        Ok(rv)
    }

    async fn get_values(&self) -> Result<Vec<ReferenceValue>> {
        let _ = self.lock.read().await;
        let file = tokio::fs::read(&self.file_path).await?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        Ok(rvs)
    }
}
