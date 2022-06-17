use crate::management_api::Tee;
use anyhow::{anyhow, Context, Result};
use log::Level;
use std::fs;
use std::io::prelude::*;
use std::path::Path;

use crate::management_api::management_service_client::ManagementServiceClient;
use crate::management_api::{
    GetPolicyRequest, GetPolicyResponse, GetReferenceDataRequest, GetReferenceDataResponse,
    RestoreDefaultPolicyRequest, RestoreDefaultReferenceDataRequest, SetPolicyRequest,
    SetReferenceDataRequest,
};

pub const DEFAULT_MANAGEMENT_ADDR: &str = "https://127.0.0.1:3001";

impl Tee {
    fn from_str(tee: &str) -> Result<Tee> {
        match tee {
            "sgx" => Ok(Tee::Sgx),
            "tdx" => Ok(Tee::Tdx),
            "sevsnp" => Ok(Tee::SevSnp),
            "sample" => Ok(Tee::Sample),
            _ => Err(anyhow!("TEE: {} is not supported", tee)),
        }
    }
}

pub async fn set_policy_cmd(tee: &str, file: &Path, address: &str) -> Result<()> {
    let policy = fs::read_to_string(file).context(anyhow!("Read policy error"))?;

    let request = SetPolicyRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
        content: policy.into_bytes(),
    };

    let mut client = ManagementServiceClient::connect(address.to_string()).await?;
    client.set_policy(request).await?;
    Ok(())
}

pub async fn set_reference_data_cmd(tee: &str, file: &Path, address: &str) -> Result<()> {
    let reference_data = fs::read_to_string(file).context(anyhow!("Read reference data error"))?;

    let request = SetReferenceDataRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
        content: reference_data.into_bytes(),
    };

    let mut client = ManagementServiceClient::connect(address.to_string()).await?;
    client.set_reference_data(request).await?;
    Ok(())
}

pub async fn get_policy_cmd(tee: &str, output_path: &Path, address: &str) -> Result<()> {
    let request = GetPolicyRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(address.to_string()).await?;
    let response: GetPolicyResponse = client.get_policy(request).await?.into_inner();
    let policy = String::from_utf8(response.content).unwrap();
    log!(Level::Info, "{}", &policy);

    fs::File::create(output_path)
        .context(anyhow!("create file failed"))?
        .write_all(policy.as_bytes())
        .context(anyhow!("write failed"))?;

    Ok(())
}

pub async fn get_reference_data_cmd(tee: &str, output_path: &Path, address: &str) -> Result<()> {
    let request = GetReferenceDataRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(address.to_string()).await?;
    let response: GetReferenceDataResponse = client.get_reference_data(request).await?.into_inner();
    let reference_data = String::from_utf8(response.content).unwrap();
    log!(Level::Info, "{}", &reference_data);

    fs::File::create(output_path)
        .context(anyhow!("create file failed"))?
        .write_all(reference_data.as_bytes())
        .context(anyhow!("write failed"))?;

    Ok(())
}

pub async fn restore_default_policy_cmd(tee: &str, address: &str) -> Result<()> {
    let request = RestoreDefaultPolicyRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(address.to_string()).await?;
    client.restore_default_policy(request).await?;
    Ok(())
}

pub async fn restore_default_reference_data_cmd(tee: &str, address: &str) -> Result<()> {
    let request = RestoreDefaultReferenceDataRequest {
        tee: Tee::from_str(tee)? as i32,
        user: None,
    };

    let mut client = ManagementServiceClient::connect(address.to_string()).await?;
    client.restore_default_reference_data(request).await?;
    Ok(())
}
