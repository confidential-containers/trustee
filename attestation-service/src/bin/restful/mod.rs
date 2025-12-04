use std::{collections::HashMap, sync::Arc};

use actix_web::{body::BoxBody, web, HttpRequest, HttpResponse, ResponseError};
use anyhow::{anyhow, bail, Context};
use attestation_service::{
    AttestationService, HashAlgorithm, InitDataInput as InnerInitDataInput,
    RuntimeData as InnerRuntimeData, VerificationRequest,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kbs_types::Tee;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use strum::AsRefStr;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{debug, error, info, instrument, Span};
use uuid::Uuid;

#[derive(Error, Debug, AsRefStr)]
pub enum Error {
    #[error("An internal error occured: {0}")]
    InternalError(#[from] anyhow::Error),
}

impl ResponseError for Error {
    fn error_response(&self) -> HttpResponse {
        match self {
            Error::InternalError(e) => {
                let mut res = HttpResponse::InternalServerError();
                let error_stack = e
                    .chain()
                    .enumerate()
                    .map(|(i, cause)| format!("{i}: {cause}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                let body = format!("An internal error occured: \n{error_stack}");
                error!("{body}");
                res.body(BoxBody::new(body))
            }
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize)]
pub struct AttestationRequest {
    verification_requests: Vec<IndividualAttestationRequest>,
    policy_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct IndividualAttestationRequest {
    tee: String,
    evidence: String,
    runtime_data: Option<RuntimeData>,
    init_data: Option<InitDataInput>,
    runtime_data_hash_algorithm: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengeRequest {
    // ChallengeRequest uses HashMap to pass variables like:
    // tee, tee_params etc
    #[serde(flatten)]
    inner: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RuntimeData {
    Raw(String),
    Structured(Value),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitDataInput {
    InitDataDigest(String),
    InitDataToml(String),
}

fn to_tee(tee: &str) -> anyhow::Result<Tee> {
    let res = match tee {
        "az-snp-vtpm" => Tee::AzSnpVtpm,
        "sgx" => Tee::Sgx,
        "snp" => Tee::Snp,
        "tdx" => Tee::Tdx,
        "cca" => Tee::Cca,
        "csv" => Tee::Csv,
        "sample" => Tee::Sample,
        "sampledevice" => Tee::SampleDevice,
        "az-tdx-vtpm" => Tee::AzTdxVtpm,
        "se" => Tee::Se,
        "hygondcu" => Tee::HygonDcu,
        other => bail!("tee `{other} not supported`"),
    };

    Ok(res)
}

fn parse_runtime_data(data: RuntimeData) -> Result<InnerRuntimeData> {
    let res = match data {
        RuntimeData::Raw(raw) => {
            let data = URL_SAFE_NO_PAD
                .decode(raw)
                .context("base64 decode raw runtime data")?;
            InnerRuntimeData::Raw(data)
        }
        RuntimeData::Structured(structured) => InnerRuntimeData::Structured(structured),
    };

    Ok(res)
}

fn parse_init_data(data: InitDataInput) -> Result<InnerInitDataInput> {
    let res = match data {
        InitDataInput::InitDataDigest(raw) => {
            let data = URL_SAFE_NO_PAD
                .decode(raw)
                .context("base64 decode raw init data")?;
            InnerInitDataInput::Digest(data)
        }
        InitDataInput::InitDataToml(structured) => InnerInitDataInput::Toml(structured),
    };

    Ok(res)
}

/// This handler uses json extractor
#[instrument(skip_all, fields(request_id = tracing::field::Empty))]
pub async fn attestation(
    request: web::Json<AttestationRequest>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request_id = Uuid::new_v4().to_string();
    Span::current().record("request_id", tracing::field::display(&request_id));
    info!("Attestation API called.");

    let request = request.into_inner();
    debug!("attestation: {request:#?}");

    let mut verification_requests: Vec<VerificationRequest> = vec![];
    for attestation_request in request.verification_requests {
        let evidence = URL_SAFE_NO_PAD
            .decode(&attestation_request.evidence)
            .context("base64 decode evidence")?;

        let evidence =
            serde_json::from_slice(&evidence).context("failed to parse evidence as JSON")?;

        let tee = to_tee(&attestation_request.tee)?;

        let runtime_data = attestation_request
            .runtime_data
            .map(parse_runtime_data)
            .transpose()
            .context("decode given Runtime Data")?;

        let init_data = attestation_request
            .init_data
            .map(parse_init_data)
            .transpose()
            .context("decode given Init Data")?;

        let runtime_data_hash_algorithm = match attestation_request.runtime_data_hash_algorithm {
            Some(alg) => HashAlgorithm::try_from(&alg[..])
                .context("parse runtime data HashAlgorithm failed")?,
            None => {
                info!("No Runtime Data Hash Algorithm provided, use `sha384` by default.");
                HashAlgorithm::Sha384
            }
        };

        verification_requests.push(VerificationRequest {
            evidence,
            tee,
            runtime_data,
            runtime_data_hash_algorithm,
            init_data,
        });
    }

    let policy_ids = if request.policy_ids.is_empty() {
        info!("no policy specified. `default` will be used");
        vec!["default".into()]
    } else {
        request.policy_ids
    };

    let token = cocoas
        .read()
        .await
        .evaluate(verification_requests, policy_ids)
        .await
        .context("attestation report evaluate")?;
    debug!("Attestation Token: {token}");
    info!("AttestationEvaluate succeeded.");
    Ok(HttpResponse::Ok().body(token))
}

#[derive(Deserialize, Debug)]
pub struct SetPolicyInput {
    policy_id: String,
    policy: String,
}

/// This handler uses json extractor with limit
#[instrument(skip_all, fields(request_id = tracing::field::Empty))]
pub async fn set_policy(
    input: web::Json<SetPolicyInput>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request_id = Uuid::new_v4().to_string();
    Span::current().record("request_id", tracing::field::display(&request_id));
    info!("Set Policy API called.");
    let input = input.into_inner();

    debug!("set policy: {input:#?}");
    cocoas
        .write()
        .await
        .set_policy(input.policy_id, input.policy)
        .await
        .context("set policy")?;
    info!("SetPolicy succeeded.");
    Ok(HttpResponse::Ok().body(""))
}

/// This handler uses json extractor
#[instrument(skip_all, fields(request_id = tracing::field::Empty))]
pub async fn get_challenge(
    request: web::Json<ChallengeRequest>,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request_id = Uuid::new_v4().to_string();
    Span::current().record("request_id", tracing::field::display(&request_id));
    info!("GetChallenge API called.");
    let request: ChallengeRequest = request.into_inner();

    debug!("GetChallenge: {request:#?}");
    let inner_tee = request
        .inner
        .get("tee")
        .as_ref()
        .map(|s| s.as_str())
        .ok_or(anyhow!("Failed to get inner tee"))?;
    let tee_params = request
        .inner
        .get("tee_params")
        .ok_or(anyhow!("Failed to get inner tee_params"))?;

    let tee = to_tee(inner_tee)?;
    let challenge = cocoas
        .read()
        .await
        .generate_supplemental_challenge(tee, tee_params.to_string())
        .await
        .context("generate challenge")?;
    info!("GetChallenge succeeded.");
    Ok(HttpResponse::Ok().body(challenge))
}

/// GET /policy
/// GET /policy/{policy_id}
///
/// The returned body would look like
/// ```json
/// [
///     {"policy-id": <id-1>, "policy-hash": <hash-1>},
///     {"policy-id": <id-2>, "policy-hash": <hash-2>},
///     ...
/// ]
/// ```
#[instrument(skip_all, fields(request_id = tracing::field::Empty))]
pub async fn get_policies(
    request: HttpRequest,
    cocoas: web::Data<Arc<RwLock<AttestationService>>>,
) -> Result<HttpResponse> {
    let request_id = Uuid::new_v4().to_string();
    Span::current().record("request_id", tracing::field::display(&request_id));
    info!("GetPolicy called.");

    match request.match_info().get("policy_id") {
        Some(policy_id) => {
            info!("Get specific policy: {policy_id}");
            let policy = cocoas
                .read()
                .await
                .get_policy(policy_id.to_string())
                .await
                .context("get policy")?;
            info!("GetPolicy succeeded.");
            Ok(HttpResponse::Ok().body(policy))
        }
        None => {
            info!("Get all policies");
            let policy_list = cocoas
                .read()
                .await
                .list_policies()
                .await
                .context("get policies")?
                .into_iter()
                .map(|(id, digest)| json!({"policy-id": id, "policy-hash": digest}))
                .collect::<Vec<_>>();

            let policy_list =
                serde_json::to_string(&policy_list).context("serialize response body")?;
            info!("GetPolicy succeeded.");
            Ok(HttpResponse::Ok().body(policy_list))
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RemovePolicyRequest {
    pub policy_ids: Vec<String>,
}
