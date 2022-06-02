use anyhow::Result;
use std::path::{Path, PathBuf};
use tokio::fs;

const DEFAULT_USER_ID: &str = "default";
const POLICY_NAME: &str = "policy.rego";
const REFERENCE_DATA_NAME: &str = "reference_data.json";

#[derive(Debug, Default)]
pub struct User {
    id: String,
}

impl User {
    pub fn default() -> Self {
        Self {
            id: DEFAULT_USER_ID.to_owned(),
        }
    }

    #[allow(dead_code)]
    pub fn from_str(id: &str) -> Result<Self> {
        Ok(Self { id: id.to_owned() })
    }

    // Fetch the users working directory.
    fn workdir(&self, dir: &Path, tee: String) -> PathBuf {
        dir.join("users").join(&self.id).join(tee)
    }

    pub async fn policy(&self, dir: &Path, tee: String) -> Result<Option<String>> {
        let file = self.workdir(dir, tee).join(POLICY_NAME);
        let policy = match file.exists() {
            true => Some(fs::read_to_string(file).await?),
            false => None,
        };
        Ok(policy)
    }

    pub async fn reference_data(&self, dir: &Path, tee: String) -> Result<Option<String>> {
        let file = self.workdir(dir, tee).join(REFERENCE_DATA_NAME);
        let reference_data = match file.exists() {
            true => Some(fs::read_to_string(file).await?),
            false => None,
        };
        Ok(reference_data)
    }

    pub async fn set_policy(&self, dir: &Path, tee: String, content: String) -> Result<()> {
        let path = self.workdir(dir, tee);
        if !path.exists() {
            fs::create_dir_all(path.as_path()).await?;
        }
        let file = path.join(POLICY_NAME);
        fs::write(file.as_path(), &content).await?;
        Ok(())
    }

    pub async fn set_reference_data(&self, dir: &Path, tee: String, content: String) -> Result<()> {
        let path = self.workdir(dir, tee);
        if !path.exists() {
            fs::create_dir_all(path.as_path()).await?;
        }
        let file = path.join(REFERENCE_DATA_NAME);
        fs::write(file.as_path(), &content).await?;
        Ok(())
    }

    pub async fn delete_policy(&self, dir: &Path, tee: String) -> Result<()> {
        let file = self.workdir(dir, tee).join(POLICY_NAME);
        if file.exists() {
            fs::remove_file(file.as_path()).await?;
        }
        Ok(())
    }

    pub async fn delete_reference_data(&self, dir: &Path, tee: String) -> Result<()> {
        let file = self.workdir(dir, tee).join(REFERENCE_DATA_NAME);
        if file.exists() {
            fs::remove_file(file.as_path()).await?;
        }
        Ok(())
    }
}
