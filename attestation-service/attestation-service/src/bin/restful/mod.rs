use std::sync::Arc;

use actix_web::{body::BoxBody, web, HttpResponse, ResponseError};
use anyhow::{bail, Context};
use attestation_service::{policy_engine::SetPolicyInput, AttestationService, HashAlgorithm};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::Tee;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use strum::AsRefStr;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Error, Debug, AsRefStr)]
pub enum Error {
    #[error("An internal error occured: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        let body = format!("{self:#?}");

        let mut res = match self {
            Error::InternalError(_) => HttpResponse::InternalServerError(),
            // _ => HttpResponse::NotImplemented(),
        };

        res.body(BoxBody::new(body))
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    tee: String,
    evidence: String,
    runtime_data: Option<Data>,
    init_data: Option<Data>,
    runtime_data_hash_algorithm: Option<String>,
    init_data_hash_algorithm: Option<String>,
    policy_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Data {
    Raw(String),
    Structured(Value),
}

fn to_tee(tee: &str) -> anyhow::Result<Tee> {
    let res = match tee {
        "azsnpvtpm" => Tee::AzSnpVtpm,
        "sev" => Tee::Sev,
        "sgx" => Tee::Sgx,
        "snp" => Tee::Snp,
        "tdx" => Tee::Tdx,
        "cca" => Tee::Cca,
        "csv" => Tee::Csv,
        "sample" => Tee::Sample,
        "aztdxvtpm" => Tee::AzTdxVtpm,
        other => bail!("tee `{other} not supported`"),
    };

    Ok(res)
}

fn parse_data(data: Data) -> Result<attestation_service::Data> {
    let res = match data {
        Data::Raw(raw) => {
            let data = URL_SAFE_NO_PAD
                .decode(raw)
                .context("base64 decode raw data")?;
            attestation_service::Data::Raw(data)
        }
        Data::Structured(structured) => attestation_service::Data::Structured(structured),
    };

    Ok(res)
}

/// This handler uses json extractor
pub async fn attestation(
    request: web::Json<AttestationRequest>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("new attestation request.");

    let request = request.into_inner();
    debug!("attestation: {request:#?}");

    let evidence = URL_SAFE_NO_PAD
        .decode(&request.evidence)
        .context("base64 decode evidence")?;

    let tee = to_tee(&request.tee)?;

    let runtime_data = request
        .runtime_data
        .map(parse_data)
        .transpose()
        .context("decode given Runtime Data")?;

    let init_data = request
        .init_data
        .map(parse_data)
        .transpose()
        .context("decode given Init Data")?;

    let runtime_data_hash_algorithm = match request.runtime_data_hash_algorithm {
        Some(alg) => {
            HashAlgorithm::try_from(&alg[..]).context("parse runtime data HashAlgorithm failed")?
        }
        None => {
            info!("No Runtime Data Hash Algorithm provided, use `sha384` by default.");
            HashAlgorithm::Sha384
        }
    };

    let init_data_hash_algorithm = match request.init_data_hash_algorithm {
        Some(alg) => {
            HashAlgorithm::try_from(&alg[..]).context("parse init data HashAlgorithm failed")?
        }
        None => {
            info!("No Init Data Hash Algorithm provided, use `sha384` by default.");
            HashAlgorithm::Sha384
        }
    };

    let policy_ids = if request.policy_ids.is_empty() {
        info!("no policy specified, use `default`");
        vec!["default".into()]
    } else {
        request.policy_ids
    };

    let token = cocoas
        .read()
        .await
        .evaluate(
            evidence,
            tee,
            runtime_data,
            runtime_data_hash_algorithm,
            init_data,
            init_data_hash_algorithm,
            policy_ids,
        )
        .await
        .context("attestation report evaluate")?;
    Ok(HttpResponse::Ok().body(token))
}

/// This handler uses json extractor with limit
pub async fn set_policy(
    input: web::Json<SetPolicyInput>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    info!("set policy.");
    let input = input.into_inner();

    debug!("set policy: {input:#?}");
    cocoas
        .write()
        .await
        .set_policy(input)
        .await
        .context("set policy")?;

    Ok(HttpResponse::Ok().body(""))
}
