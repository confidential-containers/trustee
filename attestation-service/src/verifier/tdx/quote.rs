use anyhow::{anyhow, bail, Result};
use core::fmt;
use qvl::{
    sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};
use scroll::Pread;
use std::convert::TryInto;
use std::mem;
use std::time::{Duration, SystemTime};

use sgx_dcap_quoteverify_rs as qvl;

pub const QUOTE_PAYLOAD_SIZE: usize = 632;

/// The quote header. It is designed to compatible with earlier versions of the quote.
#[repr(C)]
#[derive(Debug, Pread)]
pub struct QuoteHeader {
    ///< 0:  The version this quote structure.
    pub version: u16,
    ///< 2:  sgx_attestation_algorithm_id_t.  Describes the type of signature in the signature_data[] field.
    pub att_key_type: u16,
    ///< 4:  Type of Trusted Execution Environment for which the Quote has been generated.
    ///      Supported values: 0 (SGX), 0x81(TDX)
    pub tee_type: u32,
    ///< 8:  Reserved field.
    pub reserved: u32,
    ///< 12: Unique identifier of QE Vendor.
    pub vendor_id: [u8; 16],
    ///< 28: Custom attestation key owner data.
    pub user_data: [u8; 20],
}

impl fmt::Display for QuoteHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Quote Header:
            \n\tVersion:\n\t{:X?}
            \n\tAttestation Signature Key Type:\n\t{:X?}
            \n\tTEE Type:\n\t{:X?}
            \n\tReserved:\n\t{:X?}
            \n\tVendor ID:\n\t{:X?}
            \n\tUser Data:\n\t{:X?}\n",
            self.version,
            self.att_key_type,
            self.tee_type,
            self.reserved,
            hex::encode(self.vendor_id),
            hex::encode(self.user_data)
        )
    }
}

/// SGX Report2 body
#[repr(C)]
#[derive(Debug, Pread)]
pub struct ReportBody {
    ///<  0:  TEE_TCB_SVN Array
    pub tcb_svn: [u8; 16],
    ///< 16:  Measurement of the SEAM module
    pub mr_seam: [u8; 48],
    ///< 64:  Measurement of a 3rd party SEAM module’s signer (SHA384 hash).
    ///       The value is 0’ed for Intel SEAM module
    pub mrsigner_seam: [u8; 48],
    ///< 112: MBZ: TDX 1.0
    pub seam_attributes: [u8; 8],
    ///< 120: TD's attributes
    pub td_attributes: [u8; 8],
    ///< 128: TD's XFAM
    pub xfam: [u8; 8],
    ///< 136: Measurement of the initial contents of the TD
    pub mr_td: [u8; 48],
    ///< 184: Software defined ID for non-owner-defined configuration on the guest TD. e.g., runtime or OS configuration
    pub mr_config_id: [u8; 48],
    ///< 232: Software defined ID for the guest TD's owner
    pub mr_owner: [u8; 48],
    ///< 280: Software defined ID for owner-defined configuration of the guest TD, e.g., specific to the workload rather than the runtime or OS
    pub mr_owner_config: [u8; 48],
    ///< 328: Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable measurement registers
    pub rtmr_0: [u8; 48],
    pub rtmr_1: [u8; 48],
    pub rtmr_2: [u8; 48],
    pub rtmr_3: [u8; 48],
    ///< 520: Additional report data
    pub report_data: [u8; 64],
}

impl fmt::Display for ReportBody {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Report Body:
            \n\tTCB SVN:\n\t{:X?}
            \n\tMRSEAM:\n\t{:X?}
            \n\tMRSIGNER_SEAM:\n\t{:X?}
            \n\tSEAM Attributes:\n\t{:X?}
            \n\tTD Attributes:\n\t{:X?}
            \n\tTD XFAM:\n\t{:X?}
            \n\tMRTD:\n\t{:X?}
            \n\tMRCONFIG ID:\n\t{:X?}
            \n\tMROWNER:\n\t{:X?}
            \n\tMROWNER_CONFIG:\n\t{:X?}
            \n\tRTMR[0]:\n\t{:X?}
            \n\tRTMR[1]:\n\t{:X?}
            \n\tRTMR[2]:\n\t{:X?}
            \n\tRTMR[3]:\n\t{:X?}
            \n\tReport Data:\n\t{:X?}",
            hex::encode(self.tcb_svn),
            hex::encode(self.mr_seam),
            hex::encode(self.mrsigner_seam),
            hex::encode(self.seam_attributes),
            hex::encode(self.td_attributes),
            hex::encode(self.xfam),
            hex::encode(self.mr_td),
            hex::encode(self.mr_config_id),
            hex::encode(self.mr_owner),
            hex::encode(self.mr_owner_config),
            hex::encode(self.rtmr_0),
            hex::encode(self.rtmr_1),
            hex::encode(self.rtmr_2),
            hex::encode(self.rtmr_3),
            hex::encode(self.report_data)
        )
    }
}

/// TD Quote Payload(Version 4)
/// First 632 bytes of TD Quote
/// Excluding the signature data attached at the end of the Quote.
///
/// Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L141
#[repr(C)]
#[derive(Debug, Pread)]
pub struct Quote {
    pub header: QuoteHeader,
    pub report_body: ReportBody,
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "TD Quote:\n{}\n{}\n", self.header, self.report_body)
    }
}

pub fn parse_tdx_quote(quote_bin: &[u8]) -> Result<Quote> {
    let quote_body = &quote_bin[..QUOTE_PAYLOAD_SIZE];
    quote_body
        .pread::<Quote>(0)
        .map_err(|e| anyhow!("Parse TD quote failed: {:?}", e))
}

pub async fn ecdsa_quote_verification(quote: &[u8]) -> Result<()> {
    let mut supp_data: sgx_ql_qv_supplemental_t = Default::default();
    let mut supp_data_desc = tee_supp_data_descriptor_t {
        major_version: 0,
        data_size: 0,
        p_data: &mut supp_data as *mut sgx_ql_qv_supplemental_t as *mut u8,
    };

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
            "tee_get_quote_supplemental_data_size failed: {:#04x}",
            e as u32
        ),
    }

    // get collateral
    let _collateral = match tee_qv_get_collateral(quote) {
        Ok(c) => {
            debug!("tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            warn!("tee_qv_get_collateral failed: {:#04x}", e as u32);
            None
        }
    };

    let p_collateral: Option<&[u8]> = None;

    // set current time. This is only for sample purposes, in production mode a trusted time should be used.
    //
    let current_time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64;

    let p_supplemental_data = match supp_data_desc.data_size {
        0 => None,
        _ => Some(&mut supp_data_desc),
    };

    // call DCAP quote verify library for quote verification
    let (collateral_expiration_status, quote_verification_result) =
        tee_verify_quote(quote, p_collateral, current_time, None, p_supplemental_data)
            .map_err(|e| anyhow!("tee_verify_quote failed: {:#04x}", e as u32))?;

    debug!("tee_verify_quote successfully returned.");

    // check verification result
    match quote_verification_result {
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OK => {
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            if collateral_expiration_status == 0 {
                debug!("Verification completed successfully.");
            } else {
                warn!("Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
            }
        }
        sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_SW_HARDENING_NEEDED
        | sgx_ql_qv_result_t::SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED => {
            warn!(
                "Verification completed with Non-terminal result: {:x}",
                quote_verification_result as u32
            );
        }
        _ => {
            bail!(
                "Verification completed with Terminal result: {:x}",
                quote_verification_result as u32
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_parse_tdx_quote() {
        let quote_bin = fs::read("../test_data/tdx_quote_4.dat").unwrap();
        let quote = parse_tdx_quote(&quote_bin);

        assert!(quote.is_ok());
        let parsed_quote = format!("{}", quote.unwrap());

        let _ = fs::write("test_data/parse_tdx_quote_output.txt", parsed_quote);
    }

    #[ignore]
    #[tokio::test]
    async fn test_verify_tdx_quote() {
        let quote_bin = fs::read("../test_data/quote.dat").unwrap();
        let res = ecdsa_quote_verification(quote_bin.as_slice()).await;
        assert!(res.is_ok(), "error");
    }
}
