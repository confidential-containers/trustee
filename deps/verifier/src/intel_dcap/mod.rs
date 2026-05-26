use crate::intel_dcap::claims::prepare_custom_claims_map;
use crate::intel_dcap::error::describe_error;
use crate::TeeEvidenceParsedClaim;
use anyhow::{anyhow, bail};
use intel_tee_quote_verification_rs::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, sgx_ql_request_policy_t,
    sgx_qv_set_enclave_load_policy, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::env;
use std::fs::File;
use std::io::{ErrorKind, Write};
use std::mem;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

mod claims;
mod error;
#[cfg(any(feature = "tdx-verifier", feature = "sgx-verifier"))]
pub(crate) mod pck;
#[cfg(any(feature = "tdx-verifier", feature = "sgx-verifier"))]
pub(crate) mod quote;

const INTEL_PCS_URL: &str = "https://api.trustedservices.intel.com/sgx/certification/v4/";

#[derive(Debug, Default, Deserialize, Clone, Serialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum TcbUpdateType {
    #[default]
    Early,
    Standard,
}

#[derive(Debug, Deserialize, Clone, Serialize, PartialEq)]
pub(crate) struct QcnlConfig {
    collateral_service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    use_secure_cert: Option<bool>,
    #[serde(default)]
    tcb_update_type: TcbUpdateType,
}

impl Default for QcnlConfig {
    fn default() -> Self {
        Self {
            collateral_service: INTEL_PCS_URL.to_string(),
            use_secure_cert: None,
            tcb_update_type: TcbUpdateType::Early,
        }
    }
}

pub(crate) fn set_qcnl_config(c: Option<QcnlConfig>) -> Result<(), std::io::Error> {
    env::var("QCNL_CONF_PATH")
        .map_err(std::io::Error::other)
        .and_then(File::create_new)
        .and_then(|mut f| {
            f.write_all(
                serde_json::to_string(&c.unwrap_or_default())
                    .map_err(|_| std::io::Error::from(ErrorKind::InvalidInput))?
                    .as_bytes(),
            )
        })
        .inspect_err(|e| match e.kind() {
            ErrorKind::Other => debug!(
                "QCNL_CONF_PATH environment variable is not set so configuration was skipped."
            ),
            ErrorKind::AlreadyExists => debug!("DCAP QCNL is already configured."),
            ErrorKind::PermissionDenied => {
                warn!("DCAP QCNL configuration failed due to permission error.")
            }
            ErrorKind::InvalidInput => {
                warn!("DCAP QCNL configuration failed due to invalid JSON.")
            }
            _ => warn!("DCAP QCNL configuration failed due to an unknown error."),
        })
        .inspect(|_| debug!("DCAP QCNL configuration was written to $QCNL_CONF_PATH."))
}

pub(crate) async fn ecdsa_quote_verification(quote: &[u8]) -> anyhow::Result<Map<String, Value>> {
    // Call DCAP quote verify library to set QvE loading policy to multi-thread
    // We only need to set the policy once; otherwise, it will return the error code 0xe00c (SGX_QL_UNSUPPORTED_LOADING_POLICY)
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        match sgx_qv_set_enclave_load_policy(
            sgx_ql_request_policy_t::SGX_QL_PERSISTENT_QVE_MULTI_THREAD,
        ) {
            quote3_error_t::SGX_QL_SUCCESS => {
                debug!("Info: sgx_qv_set_enclave_load_policy successfully returned.")
            }
            err => warn!(
                "Error: sgx_qv_set_enclave_load_policy failed: {}",
                describe_error(err)
            ),
        }
    });

    let (_, supp_size) = tee_get_supplemental_data_version_and_size(quote).map_err(|e| {
        anyhow!(
            "tee_get_supplemental_data_version_and_size failed: {}",
            describe_error(e)
        )
    })?;

    let expected_size = mem::size_of::<sgx_ql_qv_supplemental_t>() as u32;
    if supp_size != expected_size {
        bail!(
            "Supplemental data size mismatch: QVL returned {supp_size}, expected {expected_size}"
        );
    }

    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: supp_size,
        p_data: std::ptr::from_mut(&mut supp_data).cast(),
    };

    // get collateral
    let collateral = match tee_qv_get_collateral(quote) {
        Ok(c) => {
            debug!("tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            warn!("tee_qv_get_collateral failed: {}", describe_error(e));
            None
        }
    };

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) = tee_verify_quote(
        quote,
        collateral.as_ref(),
        current_time,
        None,
        Some(&mut supp_data_desc),
    )
    .map_err(|e| anyhow!("tee_verify_quote failed: {}", describe_error(e)))?;

    debug!("tee_verify_quote successfully returned.");

    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED => {
            Ok(prepare_custom_claims_map(
                &mut supp_data,
                collateral_expiration_status,
                quote_verification_result,
            ))
        }
        terminal_result => {
            bail!(
                "Verification completed with Terminal result: {:?} ({:#04x})",
                terminal_result,
                terminal_result as u32
            );
        }
    }
}

pub(crate) fn extend_using_custom_claims(
    claim: &mut TeeEvidenceParsedClaim,
    custom: Map<String, Value>,
) -> anyhow::Result<()> {
    let Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    map.extend(custom);
    anyhow::Ok(())
}
