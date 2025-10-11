use crate::intel_dcap::claims::prepare_custom_claims_map;
use crate::intel_dcap::error::describe_error;
use crate::TeeEvidenceParsedClaim;
use anyhow::{anyhow, bail};
use intel_tee_quote_verification_rs::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, sgx_ql_request_policy_t,
    sgx_qv_set_enclave_load_policy, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};
use serde_json::{Map, Value};
use std::mem;
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

mod claims;
mod error;

pub async fn ecdsa_quote_verification(quote: &[u8]) -> anyhow::Result<Map<String, Value>> {
    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

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

    match tee_get_supplemental_data_version_and_size(quote) {
        Ok((supp_ver, supp_size)) => {
            if supp_size == mem::size_of::<sgx_ql_qv_supplemental_t>() as u32 {
                debug!("tee_get_quote_supplemental_data_version_and_size successfully returned.");
                debug!(
                    "Info: latest supplemental data major version: {}, minor version: {}, size: {}",
                    u16::from_be_bytes(supp_ver.to_be_bytes()[..2].try_into()?),
                    u16::from_be_bytes(supp_ver.to_be_bytes()[2..].try_into()?),
                    supp_size,
                );
                supp_data_desc.data_size = supp_size;
            } else {
                warn!("Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.")
            }
        }
        Err(e) => bail!(
            "tee_get_quote_supplemental_data_size failed: {}",
            describe_error(e)
        ),
    }

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

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) = tee_verify_quote(
        quote,
        collateral.as_ref(),
        current_time,
        None,
        p_supplemental_data,
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

pub fn extend_using_custom_claims(
    claim: &mut TeeEvidenceParsedClaim,
    custom: Map<String, Value>,
) -> anyhow::Result<()> {
    let Value::Object(ref mut map) = claim else {
        bail!("failed to extend the claim, not an object");
    };
    map.extend(custom);
    anyhow::Ok(())
}
