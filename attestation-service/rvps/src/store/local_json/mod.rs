use std::{fs, path::PathBuf};

use super::Store;
use crate::ReferenceValue;
use anyhow::{anyhow, Result};
use log::debug;
use serde::Deserialize;
use serde_json::Value;

const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values.json";

pub struct LocalJson {
    file_path: String,
}

fn default_file_path() -> String {
    FILE_PATH.to_string()
}

#[derive(Deserialize, Default)]
struct Config {
    #[serde(default = "default_file_path")]
    file_path: String,
}

impl LocalJson {
    pub fn new(config: Value) -> Result<Self> {
        let config: Config = serde_json::from_value(config)?;

        let mut path = PathBuf::new();
        path.push(&config.file_path);

        let parent_dir = path.parent().ok_or_else(|| {
            anyhow!("Illegal `file_path` for LocalJson's config without a parent dir.")
        })?;
        debug!("create path for LocalJson: {:?}", parent_dir);
        fs::create_dir_all(parent_dir)?;
        Ok(Self {
            file_path: config.file_path,
        })
    }
}

impl Store for LocalJson {
    fn set(&mut self, name: String, rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        let file = fs::read(&self.file_path)?;
        let mut rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let mut res = None;
        if let Some(item) = rvs.iter_mut().find(|it| it.name == name) {
            res = Some(item.to_owned());
            *item = rv;
        } else {
            rvs.push(rv);
        }

        let contents = serde_json::to_vec(&rvs)?;
        fs::write(&self.file_path, contents)?;
        Ok(res)
    }

    fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let file = fs::read(&self.file_path)?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let rv = rvs.into_iter().find(|rv| rv.name == name);
        Ok(rv)
    }
}
