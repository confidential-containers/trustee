use anyhow::{anyhow, bail, Result};
use core::fmt;
use log::{debug, warn};
use qvl::{
    quote3_error_t, sgx_ql_qv_result_t, sgx_ql_qv_supplemental_t, sgx_ql_request_policy_t,
    sgx_qv_set_enclave_load_policy, tee_get_supplemental_data_version_and_size,
    tee_qv_get_collateral, tee_supp_data_descriptor_t, tee_verify_quote,
};
use scroll::Pread;
use std::mem;
use std::time::{Duration, SystemTime};

use intel_tee_quote_verification_rs as qvl;

pub const QUOTE_HEADER_SIZE: usize = 48;

/// The quote header. It is designed to compatible with earlier versions of the quote.
#[repr(C)]
#[derive(Debug, Pread)]
pub struct QuoteHeader {
    ///< 0:  The version this quote structure.
    pub version: [u8; 2],
    ///< 2:  sgx_attestation_algorithm_id_t.  Describes the type of signature in the signature_data[] field.
    pub att_key_type: [u8; 2],
    ///< 4:  Type of Trusted Execution Environment for which the Quote has been generated.
    ///      Supported values: 0 (SGX), 0x81(TDX)
    pub tee_type: [u8; 4],
    ///< 8:  Reserved field.
    pub reserved: [u8; 4],
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
            hex::encode(self.version),
            hex::encode(self.att_key_type),
            hex::encode(self.tee_type),
            hex::encode(self.reserved),
            hex::encode(self.vendor_id),
            hex::encode(self.user_data)
        )
    }
}

/// SGX Report2 body
#[repr(C)]
#[derive(Debug, Pread)]
pub struct ReportBody2 {
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

impl fmt::Display for ReportBody2 {
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

/// SGX Report2 body for quote v5
#[repr(C)]
#[derive(Debug, Pread)]
pub struct ReportBody2v15 {
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
    ///< 184: Software defined ID for non-owner-defined configuration on
    /// the guest TD. e.g., runtime or OS configuration
    pub mr_config_id: [u8; 48],
    ///< 232: Software defined ID for the guest TD's owner
    pub mr_owner: [u8; 48],
    ///< 280: Software defined ID for owner-defined configuration of the
    /// guest TD, e.g., specific to the workload rather than the runtime or OS
    pub mr_owner_config: [u8; 48],
    ///< 328: Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable
    /// measurement registers
    pub rtmr_0: [u8; 48],
    pub rtmr_1: [u8; 48],
    pub rtmr_2: [u8; 48],
    pub rtmr_3: [u8; 48],
    ///< 520: Additional report data
    pub report_data: [u8; 64],
    ///< 584: Array of TEE TCB SVNs (for TD preserving).
    pub tee_tcb_svn2: [u8; 16],
    ///< 600: If is one or more bound or pre-bound service TDs, SERVTD_HASH is
    /// the SHA384 hash of the TDINFO_STRUCTs of those service TDs bound.
    /// Else, SERVTD_HASH is 0.
    pub mr_servicetd: [u8; 48],
}

impl fmt::Display for ReportBody2v15 {
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
            \n\tReport Data:\n\t{:X?}
            \n\tTEE TCB SVN2:\n\t{:X?}
            \n\tMR SERVICETD:\n\t{:X?}",
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
            hex::encode(self.report_data),
            hex::encode(self.tee_tcb_svn2),
            hex::encode(self.mr_servicetd)
        )
    }
}

#[repr(u16)]
#[derive(Debug)]
pub enum QuoteV5Type {
    TDX10 = 2,
    TDX15 = 3,
}

impl fmt::Display for QuoteV5Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteV5Type::TDX10 => writeln!(f, "Quote v5 Type: TDX 1.0"),
            QuoteV5Type::TDX15 => writeln!(f, "Quote v5 Type: TDX 1.5"),
        }
    }
}

impl QuoteV5Type {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 2 {
            bail!("parse QuoteV5 Type failed. Bytes length < 2 bytes");
        }
        let mut r#type: [u8; 2] = [0; 2];
        r#type.copy_from_slice(&bytes[0..2]);
        let r#type = u16::from_le_bytes(r#type);
        let r#type = match r#type {
            2 => QuoteV5Type::TDX10,
            3 => QuoteV5Type::TDX15,
            others => bail!("parse QuoteV5 Type failed. {others} not defined."),
        };

        Ok(r#type)
    }

    pub fn as_bytes(&self) -> [u8; 2] {
        // The unsafe here is ok as it is marked as repr(u16)
        unsafe {
            let raw_value: u16 = *(self as *const QuoteV5Type as *const u16);
            raw_value.to_ne_bytes()
        }
    }
}

pub enum QuoteV5Body {
    Tdx10(ReportBody2),
    Tdx15(ReportBody2v15),
}

impl fmt::Display for QuoteV5Body {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteV5Body::Tdx10(body) => write!(f, "{}", body),
            QuoteV5Body::Tdx15(body) => write!(f, "{}", body),
        }
    }
}

pub enum Quote {
    /// TD Quote Payload(Version 4)
    /// First 632 bytes of TD Quote
    /// Excluding the signature data attached at the end of the Quote.
    ///
    /// Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L141
    V4 {
        header: QuoteHeader,
        body: ReportBody2,
    },

    /// TD Quote Payload(Version 5)
    /// First 638 bytes of TD Quote
    /// Excluding the signature data attached at the end of the Quote.
    ///
    /// Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h#L106
    V5 {
        header: QuoteHeader,
        r#type: QuoteV5Type,
        size: [u8; 4],
        body: QuoteV5Body,
    },
}

macro_rules! body_field {
    ($r: ident) => {
        pub fn $r(&self) -> &[u8] {
            match self {
                Quote::V4 { body, .. } => &body.$r,
                Quote::V5 { body, .. } => match body {
                    QuoteV5Body::Tdx10(body) => &body.$r,
                    QuoteV5Body::Tdx15(body) => &body.$r,
                },
            }
        }
    };
}

impl Quote {
    body_field!(report_data);
    body_field!(mr_config_id);
    body_field!(rtmr_0);
    body_field!(rtmr_1);
    body_field!(rtmr_2);
    body_field!(rtmr_3);
    body_field!(td_attributes);
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Quote::V4 { header, body } => write!(f, "TD Quote (V4):\n{header}\n{body}\n"),
            Quote::V5 {
                header,
                r#type,
                size,
                body,
            } => write!(
                f,
                "TD Quote (V5):\n{header}\n{type}\n{}\n{body}\n",
                hex::encode(size)
            ),
        }
    }
}

pub fn parse_tdx_quote(quote_bin: &[u8]) -> Result<Quote> {
    let quote_header = &quote_bin[..QUOTE_HEADER_SIZE];
    let header = quote_header
        .pread::<QuoteHeader>(0)
        .map_err(|e| anyhow!("Parse TD quote header failed: {:?}", e))?;

    match header.version {
        [4, 0] => {
            let body: ReportBody2 = quote_bin
                .pread::<ReportBody2>(QUOTE_HEADER_SIZE)
                .map_err(|e| anyhow!("Parse TD quote v4 body failed: {:?}", e))?;
            Ok(Quote::V4 { header, body })
        }
        [5, 0] => {
            let r#type = QuoteV5Type::from_bytes(
                &quote_bin
                    [QUOTE_HEADER_SIZE..QUOTE_HEADER_SIZE + std::mem::size_of::<QuoteV5Type>()],
            )?;
            let mut size: [u8; 4] = [0; 4];
            size.copy_from_slice(
                &quote_bin[QUOTE_HEADER_SIZE + std::mem::size_of::<QuoteV5Type>()
                    ..QUOTE_HEADER_SIZE
                        + std::mem::size_of::<QuoteV5Type>()
                        + std::mem::size_of::<[u8; 4]>()],
            );
            match r#type {
                QuoteV5Type::TDX10 => {
                    let offset = QUOTE_HEADER_SIZE
                        + std::mem::size_of::<QuoteV5Type>()
                        + std::mem::size_of::<[u8; 4]>();
                    let body: ReportBody2 = quote_bin
                        .pread::<ReportBody2>(offset)
                        .map_err(|e| anyhow!("Parse TD quote v5 TDX1.0 body failed: {:?}", e))?;
                    Ok(Quote::V5 {
                        header,
                        r#type,
                        size,
                        body: QuoteV5Body::Tdx10(body),
                    })
                }
                QuoteV5Type::TDX15 => {
                    let offset = QUOTE_HEADER_SIZE
                        + std::mem::size_of::<QuoteV5Type>()
                        + std::mem::size_of::<[u8; 4]>();
                    let body: ReportBody2v15 = quote_bin
                        .pread::<ReportBody2v15>(offset)
                        .map_err(|e| anyhow!("Parse TD quote v5 TDX1.5 body failed: {:?}", e))?;
                    Ok(Quote::V5 {
                        header,
                        r#type,
                        size,
                        body: QuoteV5Body::Tdx15(body),
                    })
                }
            }
        }
        _ => Err(anyhow!("Quote version not defined.")),
    }
}

pub async fn ecdsa_quote_verification(quote: &[u8]) -> Result<()> {
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
                "Error: sgx_qv_set_enclave_load_policy failed: {:#04x}",
                err as u32
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
            "tee_get_quote_supplemental_data_size failed: {:#04x}",
            e as u32
        ),
    }

    // get collateral
    let collateral = match tee_qv_get_collateral(quote) {
        Ok(c) => {
            debug!("tee_qv_get_collateral successfully returned.");
            Some(c)
        }
        Err(e) => {
            warn!("tee_qv_get_collateral failed: {:#04x}", e as u32);
            None
        }
    };

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
    let (collateral_expiration_status, quote_verification_result) = tee_verify_quote(
        quote,
        collateral.as_ref(),
        current_time,
        None,
        p_supplemental_data,
    )
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
    use rstest::rstest;

    use super::*;
    use std::fs;

    #[rstest]
    #[case("./test_data/tdx_quote_4.dat")]
    #[case("./test_data/tdx_quote_5.dat")]
    fn test_parse_tdx_quote(#[case] quote_path: &str) {
        let quote_bin = fs::read(quote_path).unwrap();
        let quote = parse_tdx_quote(&quote_bin);

        assert!(quote.is_ok());
        let parsed_quote = format!("{}", quote.unwrap());

        let _ = fs::write(format!("{quote_path}.txt"), parsed_quote);
    }

    /// Test to verify the TDX quote, both in v4 and v5 format.
    ///
    /// This unit test requires two packages, s.t. `libsgx-dcap-quote-verify-dev` and `libsgx-dcap-default-qpl`
    /// On ubuntu 22.04, you need to run the following scripts to install.
    /// ```shell
    /// curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | tee intel-sgx-deb.key | apt-key add - && \
    /// echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main' | tee /etc/apt/sources.list.d/intel-sgx.list && \
    /// apt-get update && \
    /// apt-get install -y libsgx-dcap-default-qpl libsgx-dcap-quote-verify
    /// ```
    ///
    /// Also, you need to configure DCAP to work with alibaba cloud's PCCS.
    /// edit `/etc/sgx_default_qcnl.conf` and replace the whole content with
    /// ```json
    /// {"pccs_url" :"https://sgx-dcap-server.cn-beijing.aliyuncs.com/sgx/certification/v4/"}
    /// ```
    ///
    /// The manual modification upon `sgx_default_qcnl.conf` could be promoted after
    /// https://github.com/intel/SGXDataCenterAttestationPrimitives/issues/409 is resolved.
    ///
    /// Finally, DCAP only provides packages on x86-64 platform, thus we only test this on x86-64
    /// platforms.
    #[cfg(target_arch = "x86_64")]
    #[rstest]
    #[ignore]
    #[tokio::test]
    #[case("./test_data/tdx_quote_4.dat")]
    #[ignore]
    #[tokio::test]
    #[case("./test_data/tdx_quote_5.dat")]
    async fn test_verify_tdx_quote(#[case] quote: &str) {
        let quote_bin = fs::read(quote).unwrap();
        let res = ecdsa_quote_verification(quote_bin.as_slice()).await;
        assert!(res.is_ok(), "{res:?}");
    }
}
