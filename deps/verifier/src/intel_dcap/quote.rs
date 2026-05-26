// Copyright (c) 2026 Confidential Containers Project Authors
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use core::fmt;
use scroll::Pread;
use std::mem::size_of;

/// att_key_type value for ECDSA-256-with-P-256 curve (SGX spec Table 4, value 2).
const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;

/// tee_type value for SGX (quote v3).
const TEE_TYPE_SGX: u32 = 0x00000000;

/// tee_type value for TDX (quote v4 and v5).
const TEE_TYPE_TDX: u32 = 0x00000081;

/// The quote header, layout-compatible across SGX (v3) and TDX (v4, v5).
///
/// SGX v3 quotes use the `tee_type` field as `att_key_data_0` (always 0)
/// and `reserved` encodes `qe_svn[2] || pce_svn[2]`.
#[repr(C)]
#[derive(Debug, Pread)]
pub(crate) struct QuoteHeader {
    ///< 0:  The version this quote structure.
    pub(crate) version: [u8; 2],
    ///< 2:  Describes the type of signature in the signature_data[] field.
    pub(crate) att_key_type: [u8; 2],
    ///< 4:  Type of Trusted Execution Environment.
    ///      0x00000000: SGX, 0x00000081: TDX
    pub(crate) tee_type: [u8; 4],
    ///< 8:  Reserved. (SGX v3: qe_svn[2] || pce_svn[2])
    pub(crate) reserved: [u8; 4],
    ///< 12: Unique identifier of QE Vendor.
    pub(crate) vendor_id: [u8; 16],
    ///< 28: Custom attestation key owner data.
    pub(crate) user_data: [u8; 20],
}

impl fmt::Display for QuoteHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Quote Header:
\tversion:\t{}
\tatt_key_type:\t{}
\ttee_type:\t{}
\treserved:\t{}
\tvendor_id:\t{}
\tuser_data:\t{}\n",
            hex::encode(self.version),
            hex::encode(self.att_key_type),
            hex::encode(self.tee_type),
            hex::encode(self.reserved),
            hex::encode(self.vendor_id),
            hex::encode(self.user_data)
        )
    }
}

#[repr(C)]
#[derive(Debug, Pread)]
struct QuoteSignature {
    sig_r: [u8; 32],
    sig_s: [u8; 32],
    pkey_x_coord: [u8; 32],
    pkey_y_coord: [u8; 32],
}

#[repr(C)]
#[derive(Debug, Pread)]
struct QeReport {
    report: [u8; std::mem::size_of::<SgxReportBody>()],
    sig_r: [u8; 32],
    sig_s: [u8; 32],
}

#[repr(C)]
#[derive(Debug)]
pub(crate) struct QeCertificationData {
    qe_report: QeReport,
    qe_authentication: Vec<u8>,
    pub(crate) certificates: Vec<u8>,
}

#[repr(C)]
#[derive(Debug)]
pub(crate) struct QuoteCertificationData {
    quote_signature: QuoteSignature,
    pub(crate) qe_certification_data: QeCertificationData,
}

/// SGX report body (SGX ECDSA quote v3, tee_type = 0x00000000)
#[repr(C)]
#[derive(Debug, Pread)]
pub(crate) struct SgxReportBody {
    /// (  0) Security Version of the CPU
    pub(crate) cpu_svn: [u8; 16],
    /// ( 16) Which fields defined in SSA.MISC
    pub(crate) misc_select: [u8; 4],
    /// ( 20)
    pub(crate) reserved1: [u8; 12],
    /// ( 32) ISV assigned Extended Product ID
    pub(crate) isv_ext_prod_id: [u8; 16],
    /// ( 48) attributes: flags and extended feature request mask (xfrm)
    pub(crate) attributes_flags: [u8; 8],
    pub(crate) attributes_xfrm: [u8; 8],
    /// ( 64) ENCLAVE measurement
    pub(crate) mr_enclave: [u8; 32],
    /// ( 96)
    pub(crate) reserved2: [u8; 32],
    /// (128) SIGNER measurement
    pub(crate) mr_signer: [u8; 32],
    /// (160)
    pub(crate) reserved3: [u8; 32],
    /// (192) CONFIGID
    pub(crate) config_id: [u8; 64],
    /// (256) Product ID of the Enclave
    pub(crate) isv_prod_id: [u8; 2],
    /// (258) Security Version of the Enclave
    pub(crate) isv_svn: [u8; 2],
    /// (260) CONFIGSVN
    pub(crate) config_svn: [u8; 2],
    /// (262)
    pub(crate) reserved4: [u8; 42],
    /// (304) ISV assigned Family ID
    pub(crate) isv_family_id: [u8; 16],
    /// (320) Data provided by the user
    pub(crate) report_data: [u8; 64],
}

impl fmt::Display for SgxReportBody {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "SGX Report Body:
\tcpu_svn:\t{}
\tmisc_select:\t{}
\treserved1:\t{}
\tisv_ext_prod_id:\t{}
\tattributes.flags:\t{}
\tattributes.xfrm:\t{}
\tmr_enclave:\t{}
\treserved2:\t{}
\tmr_signer:\t{}
\treserved3:\t{}
\tconfig_id:\t{}
\tisv_prod_id:\t{}
\tisv_svn:\t{}
\tconfig_svn:\t{}
\treserved4:\t{}
\tisv_family_id:\t{}
\treport_data:\t{}\n",
            hex::encode(self.cpu_svn),
            hex::encode(self.misc_select),
            hex::encode(self.reserved1),
            hex::encode(self.isv_ext_prod_id),
            hex::encode(self.attributes_flags),
            hex::encode(self.attributes_xfrm),
            hex::encode(self.mr_enclave),
            hex::encode(self.reserved2),
            hex::encode(self.mr_signer),
            hex::encode(self.reserved3),
            hex::encode(self.config_id),
            hex::encode(self.isv_prod_id),
            hex::encode(self.isv_svn),
            hex::encode(self.config_svn),
            hex::encode(self.reserved4),
            hex::encode(self.isv_family_id),
            hex::encode(self.report_data),
        )
    }
}

/// TDX report body (TDX ECDSA quote v4, and v5 TDX 1.0, tee_type = 0x00000081)
#[repr(C)]
#[derive(Debug, Pread)]
pub(crate) struct TdxReportBody {
    ///<  0:  TEE_TCB_SVN Array
    pub(crate) tcb_svn: [u8; 16],
    ///< 16:  Measurement of the SEAM module
    pub(crate) mr_seam: [u8; 48],
    ///< 64:  Measurement of a 3rd party SEAM module's signer (SHA384 hash).
    ///       The value is 0'ed for Intel SEAM module
    pub(crate) mrsigner_seam: [u8; 48],
    ///< 112: MBZ: TDX 1.0
    pub(crate) seam_attributes: [u8; 8],
    ///< 120: TD's attributes
    pub(crate) td_attributes: [u8; 8],
    ///< 128: TD's XFAM
    pub(crate) xfam: [u8; 8],
    ///< 136: Measurement of the initial contents of the TD
    pub(crate) mr_td: [u8; 48],
    ///< 184: Software defined ID for non-owner-defined configuration on the guest TD. e.g., runtime or OS configuration
    pub(crate) mr_config_id: [u8; 48],
    ///< 232: Software defined ID for the guest TD's owner
    pub(crate) mr_owner: [u8; 48],
    ///< 280: Software defined ID for owner-defined configuration of the guest TD, e.g., specific to the workload rather than the runtime or OS
    pub(crate) mr_owner_config: [u8; 48],
    ///< 328: Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable measurement registers
    pub(crate) rtmr_0: [u8; 48],
    pub(crate) rtmr_1: [u8; 48],
    pub(crate) rtmr_2: [u8; 48],
    pub(crate) rtmr_3: [u8; 48],
    ///< 520: Additional report data
    pub(crate) report_data: [u8; 64],
}

impl fmt::Display for TdxReportBody {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TDX Report Body:
\ttcb_svn:\t{}
\tmr_seam:\t{}
\tmrsigner_seam:\t{}
\tseam_attributes:\t{}
\ttd_attributes:\t{}
\txfam:\t{}
\tmr_td:\t{}
\tmr_config_id:\t{}
\tmr_owner:\t{}
\tmr_owner_config:\t{}
\trtmr_0:\t{}
\trtmr_1:\t{}
\trtmr_2:\t{}
\trtmr_3:\t{}
\treport_data:\t{}\n",
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

/// TDX report body for quote v5 (TDX 1.5, tee_type = 0x00000081)
#[repr(C)]
#[derive(Debug, Pread)]
pub(crate) struct TdxReportBodyV15 {
    ///<  0:  TEE_TCB_SVN Array
    pub(crate) tcb_svn: [u8; 16],
    ///< 16:  Measurement of the SEAM module
    pub(crate) mr_seam: [u8; 48],
    ///< 64:  Measurement of a 3rd party SEAM module's signer (SHA384 hash).
    ///       The value is 0'ed for Intel SEAM module
    pub(crate) mrsigner_seam: [u8; 48],
    ///< 112: MBZ: TDX 1.0
    pub(crate) seam_attributes: [u8; 8],
    ///< 120: TD's attributes
    pub(crate) td_attributes: [u8; 8],
    ///< 128: TD's XFAM
    pub(crate) xfam: [u8; 8],
    ///< 136: Measurement of the initial contents of the TD
    pub(crate) mr_td: [u8; 48],
    ///< 184: Software defined ID for non-owner-defined configuration on
    /// the guest TD. e.g., runtime or OS configuration
    pub(crate) mr_config_id: [u8; 48],
    ///< 232: Software defined ID for the guest TD's owner
    pub(crate) mr_owner: [u8; 48],
    ///< 280: Software defined ID for owner-defined configuration of the
    /// guest TD, e.g., specific to the workload rather than the runtime or OS
    pub(crate) mr_owner_config: [u8; 48],
    ///< 328: Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable
    /// measurement registers
    pub(crate) rtmr_0: [u8; 48],
    pub(crate) rtmr_1: [u8; 48],
    pub(crate) rtmr_2: [u8; 48],
    pub(crate) rtmr_3: [u8; 48],
    ///< 520: Additional report data
    pub(crate) report_data: [u8; 64],
    ///< 584: Array of TEE TCB SVNs (for TD preserving).
    pub(crate) tee_tcb_svn2: [u8; 16],
    ///< 600: If is one or more bound or pre-bound service TDs, SERVTD_HASH is
    /// the SHA384 hash of the TDINFO_STRUCTs of those service TDs bound.
    /// Else, SERVTD_HASH is 0.
    pub(crate) mr_servicetd: [u8; 48],
}

impl fmt::Display for TdxReportBodyV15 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "TDX Report Body (v1.5):
\ttcb_svn:\t{}
\tmr_seam:\t{}
\tmrsigner_seam:\t{}
\tseam_attributes:\t{}
\ttd_attributes:\t{}
\txfam:\t{}
\tmr_td:\t{}
\tmr_config_id:\t{}
\tmr_owner:\t{}
\tmr_owner_config:\t{}
\trtmr_0:\t{}
\trtmr_1:\t{}
\trtmr_2:\t{}
\trtmr_3:\t{}
\treport_data:\t{}
\ttee_tcb_svn2:\t{}
\tmr_servicetd:\t{}\n",
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
pub(crate) enum QuoteV5Type {
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
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self> {
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
}

pub(crate) enum QuoteV5Body {
    Tdx10(TdxReportBody),
    Tdx15(TdxReportBodyV15),
}

impl fmt::Display for QuoteV5Body {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            QuoteV5Body::Tdx10(body) => write!(f, "{}", body),
            QuoteV5Body::Tdx15(body) => write!(f, "{}", body),
        }
    }
}

/// A parsed Intel DCAP ECDSA quote.
pub(crate) enum Quote {
    /// SGX Quote v3 (tee_type = 0x00000000)
    V3 {
        header: QuoteHeader,
        body: SgxReportBody,
        cert_data: QuoteCertificationData,
    },

    /// TD Quote v4 (tee_type = 0x00000081)
    ///
    /// Refer to: https://github.com/intel/confidential-computing.tee.dcap/blob/main/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L141
    V4 {
        header: QuoteHeader,
        body: TdxReportBody,
        cert_data: QuoteCertificationData,
    },

    /// TD Quote v5 (tee_type = 0x00000081)
    ///
    /// Refer to: https://github.com/intel/confidential-computing.tee.dcap/blob/main/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h#L106
    V5 {
        header: QuoteHeader,
        r#type: QuoteV5Type,
        size: [u8; 4],
        body: QuoteV5Body,
        cert_data: QuoteCertificationData,
    },
}

impl Quote {
    pub(crate) fn cert_data(&self) -> &QuoteCertificationData {
        match self {
            Quote::V3 { cert_data, .. } => cert_data,
            Quote::V4 { cert_data, .. } => cert_data,
            Quote::V5 { cert_data, .. } => cert_data,
        }
    }
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Quote::V3 { header, body, .. } => write!(f, "SGX Quote (V3):\n{header}\n{body}\n"),
            Quote::V4 { header, body, .. } => write!(f, "TDX Quote (V4):\n{header}\n{body}\n"),
            Quote::V5 {
                header,
                r#type,
                size,
                body,
                ..
            } => write!(
                f,
                "TDX Quote (V5):\n{header}\n{type}\n{}\n{body}\n",
                hex::encode(size)
            ),
        }
    }
}

const QE_REPORT_CERT_DATA_TYPE: u16 = 6;
const PCK_CERT_CHAIN_CERT_DATA_TYPE: u16 = 5;

/// Parse the ECDSA signature + QE certification data that follows the quote body.
///
/// `is_sgx_v3`: SGX v3 quotes omit the cert-data-type (u16) and length (u32)
/// fields before the QeReport; TDX v4/v5 include them.
fn parse_certification_data(data: &[u8], is_sgx_v3: bool) -> Result<QuoteCertificationData> {
    let mut offset = 0;

    let quote_signature: QuoteSignature = data.gread::<QuoteSignature>(&mut offset)?;

    if !is_sgx_v3 {
        let qe_report_cert_data_type: u16 = data.gread::<u16>(&mut offset)?;

        // Expect QE Report Certification Data
        if qe_report_cert_data_type != QE_REPORT_CERT_DATA_TYPE {
            bail!("expected cert data type {QE_REPORT_CERT_DATA_TYPE}, got {qe_report_cert_data_type}");
        }

        // Advance past the QE Report Certification Data length field.
        _ = data.gread::<u32>(&mut offset)?;
    }

    let qe_report: QeReport = data.gread(&mut offset)?;

    let qe_auth_len: usize = data.gread::<u16>(&mut offset)? as usize;
    let qe_authentication: Vec<u8> = data
        .get(offset..offset + qe_auth_len)
        .ok_or_else(|| anyhow!("QE authentication data out of bounds"))?
        .to_vec();

    offset += qe_auth_len;
    let pck_cert_chain_type: u16 = data.gread::<u16>(&mut offset)?;

    // Expect PCK Cert Chain type
    if pck_cert_chain_type != PCK_CERT_CHAIN_CERT_DATA_TYPE {
        bail!(
            "expected cert chain type {PCK_CERT_CHAIN_CERT_DATA_TYPE}, got {pck_cert_chain_type}"
        );
    }

    let cert_len: usize = data.gread::<u32>(&mut offset)? as usize;
    let certificates = data
        .get(offset..offset + cert_len)
        .ok_or_else(|| anyhow!("PCK certificate chain data out of bounds"))?
        .to_vec();

    Ok(QuoteCertificationData {
        quote_signature,
        qe_certification_data: QeCertificationData {
            qe_report,
            qe_authentication,
            certificates,
        },
    })
}

/// Parse certification data whose 4-byte length prefix starts at `sig_len_off` in `quote_bin`.
fn parse_cert_data_at(
    quote_bin: &[u8],
    sig_len_off: usize,
    is_sgx_v3: bool,
) -> Result<QuoteCertificationData> {
    let sig_start = sig_len_off + std::mem::size_of::<u32>();

    let sig_len: [u8; 4] = quote_bin
        .get(sig_len_off..sig_start)
        .context("quote too short to read signature data length")?
        .try_into()
        .context("signature data length slice is not 4 bytes")?;

    let sig_len = u32::from_le_bytes(sig_len) as usize;

    let sig_data = quote_bin
        .get(sig_start..sig_start + sig_len)
        .context(format!(
            "quote too short for declared signature data length ({sig_len})"
        ))?;

    parse_certification_data(sig_data, is_sgx_v3)
}

/// Parse an Intel DCAP ECDSA quote (SGX v3, TDX v4, or TDX v5).
///
/// Dispatches on (version, tee_type):
/// - (3, 0x00000000) → [`Quote::V3`] (SGX)
/// - (4, 0x00000081) → [`Quote::V4`] (TDX 1.0)
/// - (5, 0x00000081) → [`Quote::V5`] (TDX 1.0 or 1.5)
pub(crate) fn parse_quote(quote_bin: &[u8]) -> Result<Quote> {
    let header = quote_bin
        .pread::<QuoteHeader>(0)
        .context("parse quote header failed")?;

    let version = u16::from_le_bytes(header.version);
    let tee_type = u32::from_le_bytes(header.tee_type);
    let att_key_type = u16::from_le_bytes(header.att_key_type);

    if att_key_type != ATT_KEY_TYPE_ECDSA_P256 {
        bail!("unsupported att_key_type {att_key_type}, expected {ATT_KEY_TYPE_ECDSA_P256} (ECDSA-256-with-P-256)");
    }

    match (version, tee_type) {
        (3, TEE_TYPE_SGX) => {
            let body = quote_bin
                .pread::<SgxReportBody>(size_of::<QuoteHeader>())
                .context("parse SGX quote body failed")?;
            let cert_data = parse_cert_data_at(
                quote_bin,
                size_of::<QuoteHeader>() + size_of::<SgxReportBody>(),
                true,
            )?;
            Ok(Quote::V3 {
                header,
                body,
                cert_data,
            })
        }
        (4, TEE_TYPE_TDX) => {
            let body = quote_bin
                .pread::<TdxReportBody>(size_of::<QuoteHeader>())
                .context("parse TDX quote v4 body failed")?;
            let cert_data = parse_cert_data_at(
                quote_bin,
                size_of::<QuoteHeader>() + size_of::<TdxReportBody>(),
                false,
            )?;
            Ok(Quote::V4 {
                header,
                body,
                cert_data,
            })
        }
        (5, TEE_TYPE_TDX) => {
            let r#type = QuoteV5Type::from_bytes(
                &quote_bin
                    [size_of::<QuoteHeader>()..size_of::<QuoteHeader>() + size_of::<QuoteV5Type>()],
            )?;
            let mut size: [u8; 4] = [0; 4];
            size.copy_from_slice(
                &quote_bin[size_of::<QuoteHeader>() + size_of::<QuoteV5Type>()
                    ..size_of::<QuoteHeader>() + size_of::<QuoteV5Type>() + size_of::<[u8; 4]>()],
            );
            let offset = size_of::<QuoteHeader>() + size_of::<QuoteV5Type>() + size_of::<[u8; 4]>();
            let (body, body_size) = match r#type {
                QuoteV5Type::TDX10 => {
                    let body = quote_bin
                        .pread::<TdxReportBody>(offset)
                        .context("parse TDX quote v5 TDX1.0 body failed")?;
                    (QuoteV5Body::Tdx10(body), size_of::<TdxReportBody>())
                }
                QuoteV5Type::TDX15 => {
                    let body = quote_bin
                        .pread::<TdxReportBodyV15>(offset)
                        .context("parse TDX quote v5 TDX1.5 body failed")?;
                    (QuoteV5Body::Tdx15(body), size_of::<TdxReportBodyV15>())
                }
            };
            let cert_data = parse_cert_data_at(quote_bin, offset + body_size, false)?;
            Ok(Quote::V5 {
                header,
                r#type,
                size,
                body,
                cert_data,
            })
        }
        (v, t) => bail!("unsupported quote version {v} / tee_type {t:#010x}"),
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::intel_dcap::ecdsa_quote_verification;
    use std::fs;

    #[rstest]
    #[case("./test_data/occlum_quote.dat", 3)]
    #[case("./test_data/tdx_quote_4.dat", 4)]
    #[case("./test_data/tdx_quote_5.dat", 5)]
    fn test_quote_version(#[case] quote_path: &str, #[case] expected_version: u16) {
        let quote_bin = fs::read(quote_path).unwrap();
        let quote = parse_quote(&quote_bin).expect("parse quote");
        let version = match &quote {
            Quote::V3 { header, .. } => u16::from_le_bytes(header.version),
            Quote::V4 { header, .. } => u16::from_le_bytes(header.version),
            Quote::V5 { header, .. } => u16::from_le_bytes(header.version),
        };
        assert_eq!(version, expected_version);
    }

    #[rstest]
    #[case("./test_data/tdx_quote_4.dat")]
    #[case("./test_data/tdx_quote_5.dat")]
    fn test_parse_tdx_quote(#[case] quote_path: &str) {
        let quote_bin = fs::read(quote_path).unwrap();
        let quote = parse_quote(&quote_bin);

        assert!(quote.is_ok());
        let parsed_quote = format!("{}", quote.unwrap());

        let _ = fs::write(format!("{quote_path}.txt"), parsed_quote);
    }

    #[rstest]
    #[case("./test_data/occlum_quote.dat")]
    fn test_parse_sgx_quote(#[case] quote_path: &str) {
        let quote_bin = fs::read(quote_path).unwrap();
        let quote = parse_quote(&quote_bin);

        assert!(quote.is_ok());
        let parsed_quote = format!("{}", quote.unwrap());
        let _ = fs::write("./test_data/parse_sgx_quote_output.txt", parsed_quote);
    }

    /// Test to verify the TDX quote, both in v4 and v5 format.
    ///
    /// This unit test requires two packages, s.t. `libsgx-dcap-quote-verify-dev` and `libsgx-dcap-default-qpl`
    /// On ubuntu 24.04, you need to run the following scripts to install.
    /// ```shell
    /// curl -L https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo gpg --dearmor --output /usr/share/keyrings/intel-sgx.gpg && \
    /// echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx.gpg] https://download.01.org/intel-sgx/sgx_repo/ubuntu noble main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list && \
    /// sudo apt-get update && \
    /// sudo apt-get install -y libsgx-dcap-quote-verify-dev libsgx-dcap-default-qpl
    /// ```
    ///
    /// Also, you need to configure DCAP to work with alibaba cloud's PCCS.
    /// create `/tmp/sgx_test_qcnl.conf` with content
    /// ```json
    /// {"collateral_service" :"https://sgx-dcap-server.cn-beijing.aliyuncs.com/sgx/certification/v4/"}
    /// ```
    /// Test can be run using exported environment variable:
    /// ```QCNL_CONF_PATH=/tmp/sgx_test_qcnl.conf```
    ///
    /// Finally, DCAP only provides packages on x86-64 platform, thus we only test this on x86-64
    /// platforms.
    #[cfg(target_arch = "x86_64")]
    #[rstest]
    #[ignore]
    #[tokio::test]
    #[case(
        "./test_data/tdx_quote_4.dat",
        r#"{"advisory_ids":["INTEL-SA-00837","INTEL-SA-00960","INTEL-SA-00982","INTEL-SA-00986","INTEL-SA-01010","INTEL-SA-01036","INTEL-SA-01076","INTEL-SA-01079","INTEL-SA-01099","INTEL-SA-01103","INTEL-SA-01111"],"collateral_expiration_status":"0","earliest_expiration_date":"2026-01-06T15:39:51Z","earliest_issue_date":"2018-05-21T10:45:10Z","is_cached_keys":true,"is_dynamic_platform":true,"is_smt_enabled":true,"latest_issue_date":"2025-12-07T15:45:03Z","pck_crl_num":1,"platform_provider_id":"df4c32a9d8d86009aaf380ec43cfcefb","root_ca_crl_num":1,"root_key_id":"46e403bd34f05a3f2817ab9badcaacc7ffc98e0f261008cd30dae936cace18d5dcf58eef31463613de1570d516200993","sgx_type":"Scalable","tcb_date":"2023-02-15T00:00:00Z","tcb_eval_num":1,"tcb_status":"OutOfDate"}"#
    )]
    #[ignore]
    #[tokio::test]
    #[case(
        "./test_data/tdx_quote_5.dat",
        r#"{"advisory_ids":[],"collateral_expiration_status":"1","earliest_expiration_date":"2024-10-08T23:59:59Z","earliest_issue_date":"2018-05-21T10:45:10Z","is_cached_keys":true,"is_dynamic_platform":true,"is_smt_enabled":true,"latest_issue_date":"2025-12-07T15:45:01Z","pck_crl_num":1,"platform_provider_id":"f06984c8d9343452b997c48b36d6e678","root_ca_crl_num":1,"root_key_id":"46e403bd34f05a3f2817ab9badcaacc7ffc98e0f261008cd30dae936cace18d5dcf58eef31463613de1570d516200993","sgx_type":"Scalable","tcb_date":"2023-08-09T00:00:00Z","tcb_eval_num":1,"tcb_status":"UpToDate"}"#
    )]
    async fn test_verify_tdx_quote(#[case] quote: &str, #[case] expected_output: &str) {
        let quote_bin = fs::read(quote).unwrap();
        let res = ecdsa_quote_verification(quote_bin.as_slice()).await;
        assert!(res.is_ok(), "{res:?}");

        let claims = serde_json::to_string(&res.unwrap()).expect("Custom claims are available.");

        assert_eq!(
            claims, expected_output,
            "Unexpected verification output for {quote}"
        );
    }
}
