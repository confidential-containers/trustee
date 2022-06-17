use anyhow::{anyhow, Result};
use log::Level;
use std::fs;
use std::path::Path;

use crate::attestation_api::attestation_service_client::AttestationServiceClient;
use crate::attestation_api::{AttestationRequest, AttestationResponse};

pub const DEFAULT_ATTESTATION_ADDR: &str = "https://127.0.0.1:3000";

pub async fn attestation_cmd(evidence_path: &Path, address: &str) -> Result<()> {
    let evidence =
        fs::read_to_string(evidence_path).map_err(|e| anyhow!("Read evidence error: {:?}", e))?;

    let request = AttestationRequest {
        evidence: evidence.into_bytes(),
        user: None,
    };

    // This can connect to Attestation-Server deployed locally or remotely.
    let mut client = AttestationServiceClient::connect(address.to_string()).await?;
    let response: AttestationResponse = client.attestation(request).await?.into_inner();
    let results = String::from_utf8(response.attestation_results)?;
    log!(Level::Info, "{}", results);

    Ok(())
}
