// Copyright (c) 2024 by IBM Corporation
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use anyhow::{Context, Result};
use std::io;
use std::fs;
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};

use super::backend::SandboxParams;


/// It has the fields to store the mapping between a sandbox name or id 
/// to a unique directory created by the directory manager
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub  struct SandboxDirectoryInfo {
    id: String,
    ip: String,
    name: String,
    sandbox_dir: PathBuf, 
}

impl SandboxDirectoryInfo {
    pub fn sandbox_dir(&self) -> &PathBuf {
        &self.sandbox_dir
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SandboxDirectoryMapper {
    // Maps sandbox name to SandboxDirectoryInfo
    sandbox_directory_mapper: HashMap<String, SandboxDirectoryInfo>, 
}


/// Responsible for generating, storing, or loading unique directory
/// names for each sandbox. That means it creates a unique directory
/// for a sandbox (if the directory does not already exist), and stores
/// the mapping between the sandbox name (or id) to a file
impl SandboxDirectoryMapper {
    pub fn new() -> Self {
        SandboxDirectoryMapper {
            sandbox_directory_mapper: HashMap::new(),
        }
    }

    // Generate a unique directory name from the fields
    fn generate_unique_dirname(id: &str, ip: &str, name: &str) -> String {
        format!("{}_{}_{}", name, ip, id)
    }

    // Create a directory and store it in the HashMap
    pub fn create_directory(
        &mut self, 
        plugin_dir: &Path, 
        params: &SandboxParams
    ) -> Result<SandboxDirectoryInfo> {
        
        let directory_name = SandboxDirectoryMapper::generate_unique_dirname(
            &params.id, 
            &params.ip, 
            &params.name
        );

        let directory_path: PathBuf = PathBuf::from(plugin_dir).as_path().join(&directory_name);

        // Create the directory
        fs::create_dir_all(&directory_path.clone())
            .with_context(|| format!("Create {} dir", directory_path.display()))?;

        log::info!("Directory {} created", directory_name);

        // Store directory info in the HashMap
        let dir_info = SandboxDirectoryInfo {
            id: params.id.clone(),
            ip: params.ip.clone(),
            name: params.name.clone(),
            sandbox_dir: directory_path.clone(),
        };

        self.sandbox_directory_mapper.insert(params.name.clone(), dir_info.clone());

        Ok(dir_info)
    }

    // Retrieve the directory info by name
    pub fn get_directory(&self, name: &str) -> Option<&SandboxDirectoryInfo> {
        self.sandbox_directory_mapper.get(name)
    }

    // Function to write SandboxDirectoryInfo to a JSON file
    pub fn write_to_file(
        &self, 
        dir_info: &SandboxDirectoryInfo, 
        file_path: &PathBuf
    ) -> io::Result<()> {
        
        let file = OpenOptions::new().append(true).create(true).open(file_path)?;
        let mut writer = std::io::BufWriter::new(file);
        
        // Serialize the SandboxDirectoryInfo entry and append it to the file with a newline delimiter
        serde_json::to_writer(&mut writer, &dir_info)?;
        writer.write_all(b"\n")?; // Add a newline to separate entries

        Ok(())
    }

    // Load the directory data from a JSON file
    pub fn load_from_file(file_path: PathBuf) -> Result<Self> {

        log::info!("Loading directory info: {}", file_path.display());

        let file = File::open(file_path)?;
        let reader = BufReader::new(file);

        // Create a new SandboxDirectoryMapper and populate its HashMap
        let mut mapper = SandboxDirectoryMapper::new();

        for line in reader.lines() {
            let line = line?;
            let entry: SandboxDirectoryInfo = serde_json::from_str(&line)?;
            log::info!("{:?}", entry);
            mapper.sandbox_directory_mapper.insert(entry.name.clone(), entry);
        }

        Ok(mapper)
    }
}