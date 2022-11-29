// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

// Copyright (c) 2022 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

//! # in-toto Extractor
//!
//! This Extractor helps to verify in-toto metadata and extract
//! related reference value from link file.

pub mod shim;

use std::{
    collections::HashMap,
    env,
    fs::{create_dir_all, File},
    io::Write,
};

use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::rvps::{reference_value::REFERENCE_VALUE_VERSION, ReferenceValue};

use super::Extractor;

/// The default in-toto metadata version
static INTOTO_VERSION: &str = "0.9";

/// Provenance contains information including the following:
/// * `version`: version field of the given in-toto metadata
/// * `line_normalization`: whether Windows-style line separators
/// (CRLF) are normalized to Unix-style line separators (LF) for
/// cross-platform consistency.
/// * `files`: a key-value map. Keys are relative paths and the
/// values are base64-encoded content of the file.
#[derive(Serialize, Deserialize)]
pub struct Provenance {
    #[serde(default = "default_version")]
    version: String,
    line_normalization: bool,
    files: HashMap<String, String>,
}

/// Use to set default version of Provenance
fn default_version() -> String {
    INTOTO_VERSION.into()
}

pub struct InTotoExtractor;

impl InTotoExtractor {
    pub fn new() -> Self {
        InTotoExtractor
    }
}

impl Extractor for InTotoExtractor {
    /// In-toto's Extractor.
    ///
    /// It will verify given provenance of in-toto using
    /// Rust-wrappered in-toto-golang. If the verification
    /// succeeds, the ReferenceValues of the resulted link
    /// file will be extracted.
    ///
    /// The verification process will create a tempdir
    /// to store the metadata, and do the verification.
    fn verify_and_extract(&self, provenance: &str) -> Result<Vec<ReferenceValue>> {
        // Deserialize Provenance
        let payload: Provenance = serde_json::from_str(provenance)?;

        // Judge version
        if payload.version != INTOTO_VERSION {
            return Err(anyhow!(
                "Version unmatched! Need {}, given {}.",
                INTOTO_VERSION,
                payload.version
            ));
        }

        // Create tempdir and put the files
        let tempdir = tempfile::tempdir()?;
        let tempdir_path = tempdir.path().to_owned();
        let tempdir_str = tempdir.path().to_string_lossy().to_string();

        let mut file_paths = Vec::new();
        for (relative_path, content_base64) in &payload.files {
            let (file_path, dir) = get_file_path(&tempdir_str[..], relative_path);
            create_dir_all(dir)?;
            let mut file = File::create(&file_path)?;
            let bytes = base64::decode(content_base64)?;
            file.write_all(&bytes)?;

            file_paths.push(file_path);
        }

        // get link dir (temp dir)
        debug!(
            "tempdir_path = {:?}, use temp path to store metadata",
            tempdir.path()
        );

        // get layout file
        let layout_path = file_paths
            .iter()
            .find(|&k| k.ends_with(".layout"))
            .ok_or_else(|| anyhow!("Layout file not found."))?
            .to_owned();

        // get pub keys
        let pub_key_paths = file_paths
            .iter()
            .filter(|&k| k.ends_with(".pub"))
            .map(|k| k.to_owned())
            .collect();

        let intermediate_paths = Vec::new();

        let line_normalization = payload.line_normalization;

        // Store and change current dir to the tmp dir
        let cwd = env::current_dir()?;

        // Read layout for the expired time
        let layout_file = std::fs::File::open(&layout_path)?;

        // A layout's expired time will be in signed.expires
        let expires = {
            let layout = &serde_json::from_reader::<_, Value>(layout_file)?["signed"]["expires"];
            if *layout == json!(null) {
                bail!("illegal layout format");
            }

            let expire_str = layout
                .as_str()
                .ok_or_else(|| anyhow!("failed to get expired time"))?;
            let ndt = NaiveDateTime::parse_from_str(expire_str, "%Y-%m-%dT%H:%M:%SZ")?;

            DateTime::<Utc>::from_utc(ndt, Utc)
        };

        env::set_current_dir(tempdir_path)?;

        let summary_link = match shim::verify(
            layout_path,
            pub_key_paths,
            intermediate_paths,
            tempdir_str,
            line_normalization,
        ) {
            Ok(summary_link) => summary_link,
            Err(e) => {
                env::set_current_dir(cwd)?;
                bail!(e);
            }
        };

        debug!(
            "summary_link = {:?}, verify in-toto metadata succeeded",
            summary_link
        );

        // Change back working dir
        env::set_current_dir(cwd)?;

        let mut res = Vec::new();

        for (filepath, digests) in &summary_link.products {
            let filename = filepath
                .value()
                .split('/')
                .last()
                .ok_or_else(|| anyhow!("Unexpected empty product name"))?;
            let mut rv = ReferenceValue::new()?
                .set_name(filename)
                .set_version(REFERENCE_VALUE_VERSION)
                .set_expired(expires);

            for (alg, value) in digests {
                let alg = serde_json::to_string(alg)?
                    .trim_end_matches('"')
                    .trim_start_matches('"')
                    .to_string();

                let value = serde_json::to_string(value)?
                    .trim_end_matches('"')
                    .trim_start_matches('"')
                    .to_string();

                rv = rv.add_hash_value(alg.to_string(), value.to_string());
            }

            res.push(rv);
        }
        Ok(res)
    }
}

/// Given a directory of tempdir and a file's relative path,
/// output the abs path of the file that will be put in the tempdir
/// and its parent dir. For example:
/// * `/tmp/tempdir` and `dir1/file` will output `/tmp/tempdir/dir1/file` and `/tmp/tempdir/dir1`
fn get_file_path(tempdir: &str, relative_file_path: &str) -> (String, String) {
    let mut abs_path = tempdir.to_string();
    abs_path.push('/');
    abs_path.push_str(relative_file_path);
    let abs_path = path_clean::clean(&abs_path[..]);
    let dir = abs_path
        .rsplit_once('/')
        .unwrap_or((&abs_path[..], ""))
        .0
        .to_string();
    (abs_path, dir)
}

#[cfg(test)]
pub mod test {
    use std::{collections::HashMap, fs};

    use chrono::{TimeZone, Utc};
    use serial_test::serial;
    use sha2::{Digest, Sha256};
    use walkdir::WalkDir;

    use crate::rvps::{extractors::extractor_modules::Extractor, ReferenceValue};

    use super::{InTotoExtractor, Provenance, INTOTO_VERSION};

    /// Helps to get sha256 digest of the artifact
    pub fn sha256_for_in_toto_test_artifact() -> String {
        let content = fs::read("tests/in-toto/foo.tar.gz").unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let result = hasher.finalize();
        let result = format!("{:x}", result);
        result
    }

    /// Helps to generate a in-toto provenance encoded
    /// in Base64. All related files are in `<git-repo>/tests/in-toto`
    pub fn generate_in_toto_provenance() -> String {
        let mut files = HashMap::new();

        for path in WalkDir::new("tests/in-toto") {
            let path = path.unwrap();
            if path.file_type().is_dir() {
                continue;
            }

            let ent = path.path();
            let content = fs::read(&ent).unwrap();
            let file_name = ent
                .to_string_lossy()
                .to_string()
                .strip_prefix("tests/in-toto/")
                .expect("failed to strip prefix")
                .into();
            let content_base64 = base64::encode(content);

            files.insert(file_name, content_base64);
        }

        let p = Provenance {
            version: INTOTO_VERSION.into(),
            line_normalization: true,
            files,
        };

        let provenance = serde_json::to_string(&p).unwrap();
        provenance
    }

    #[test]
    #[serial]
    fn in_toto_extractor() {
        let e = InTotoExtractor::new();
        let rv = ReferenceValue::new()
            .expect("create ReferenceValue failed")
            .set_name("foo.tar.gz")
            .set_expired(Utc.with_ymd_and_hms(2030, 11, 18, 16, 6, 36).unwrap())
            .set_version("0.1.0")
            .add_hash_value("sha256".into(), sha256_for_in_toto_test_artifact());
        let rv = vec![rv];
        let provenance = generate_in_toto_provenance();
        let res = e
            .verify_and_extract(&provenance)
            .expect("verify and extract");

        assert_eq!(res, rv);
    }
}
