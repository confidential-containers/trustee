use std::fs;

use super::Store;
use crate::ReferenceValue;
use anyhow::Result;

const FILE_PATH: &str = "/opt/confidential-containers/attestation-service/reference_values.json";

#[derive(Default)]
pub struct LocalJson;

impl Store for LocalJson {
    fn set(&mut self, _name: String, _rv: ReferenceValue) -> Result<Option<ReferenceValue>> {
        unimplemented!();
    }

    fn get(&self, name: &str) -> Result<Option<ReferenceValue>> {
        let file = fs::read(FILE_PATH)?;
        let rvs: Vec<ReferenceValue> = serde_json::from_slice(&file)?;
        let rv = rvs.into_iter().find(|rv| rv.name == name);
        Ok(rv)
    }
}
