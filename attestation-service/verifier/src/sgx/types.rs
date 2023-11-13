// Copyright (c) 2023 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use core::fmt;

use scroll::Pread;

#[derive(Debug, Pread)]
pub struct sgx_attributes_t {
    pub flags: [u8; 8],
    pub xfrm: [u8; 8],
}

#[repr(C)]
#[derive(Debug, Pread)]
pub struct sgx_report_body_t {
    /// (  0) Security Version of the CPU
    pub cpu_svn: [u8; 16],

    /// ( 16) Which fields defined in SSA.MISC
    pub misc_select: [u8; 4],

    /// ( 20)
    pub reserved1: [u8; 12],

    /// ( 32) ISV assigned Extended Product ID
    pub isv_ext_prod_id: [u8; 16],

    /// ( 48) Any special Capabilities the Enclave possess
    pub attributes: sgx_attributes_t,

    /// ( 64) The value of the enclave's ENCLAVE measurement
    pub mr_enclave: [u8; 32],

    /// ( 96)
    pub reserved2: [u8; 32],

    /// (128) The value of the enclave's SIGNER measurement
    pub mr_signer: [u8; 32],

    /// (160)
    pub reserved3: [u8; 32],

    /// (192) CONFIGID
    pub config_id: [u8; 64],

    /// (256) Product ID of the Enclave
    pub isv_prod_id: [u8; 2],

    /// (258) Security Version of the Enclave
    pub isv_svn: [u8; 2],

    /// (260) CONFIGSVN
    pub config_svn: [u8; 2],

    /// (262)
    pub reserved4: [u8; 42],

    /// (304) ISV assigned Family ID
    pub isv_family_id: [u8; 16],

    /// (320) Data provided by the user
    pub report_data: [u8; 64],
}

#[repr(C)]
#[derive(Debug, Pread)]
pub struct sgx_quote_header_t {
    ///< 0:  The version this quote structure.
    pub version: [u8; 2],

    ///< 2:  sgx_attestation_algorithm_id_t.  Describes the type of
    /// signature in the signature_data[] field.
    pub att_key_type: [u8; 2],

    ///< 4:  Optionally stores additional data associated with the att_key_type.
    pub att_key_data_0: [u8; 4],

    ///< 8:  The ISV_SVN of the Quoting Enclave when the quote was generated.
    pub qe_svn: [u8; 2],

    ///< 10: The ISV_SVN of the PCE when the quote was generated.
    pub pce_svn: [u8; 2],

    ///< 12: Unique identifier of QE Vendor.
    pub vendor_id: [u8; 16],

    ///< 28: Custom attestation key owner data.
    pub user_data: [u8; 20],
}

#[repr(C)]
#[derive(Debug, Pread)]
pub struct sgx_quote3_t {
    pub header: sgx_quote_header_t,
    pub report_body: sgx_report_body_t,
    pub signature_data_len: u32,

    /// The length of the signature data is defined by `signature_data_len`,
    /// which cannot be determined at compilation time. Thus this field
    /// is just marked with a `u8` slice of length 0.
    pub signature_data: [u8; 0],
}

impl fmt::Display for sgx_quote3_t {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "
QUOTE HEADER

\tversion:\t{:X?}
\tatt_key_type:\t{:X?}
\tatt_key_data_0:\t{:X?}
\tqe_svn:\t{:X?}
\tpce_svn:\t{:X?}
\tvendor_id:\t{:X?}
\tuser_data:\t{:X?}\n",
            self.header.version,
            self.header.att_key_type,
            self.header.att_key_data_0,
            self.header.qe_svn,
            self.header.pce_svn,
            self.header.vendor_id,
            self.header.user_data,
        )?;

        write!(
            f,
            "
REPORT BODY

\tcpu_svn:\t{:X?}
\tmisc_select:\t{:X?}
\treserved1:\t{:X?}
\tisv_ext_prod_id:\t{:X?}
\tattributes:
\t\tflags:\t{:X?}
\t\txfrm:\t{:X?}
\tmr_enclave\t{:X?}
\treserved2:\t{:X?}
\tmr_signer:\t{:X?}
\treserved3:\t{:X?}
\tconfig_id:\t{:X?}
\tisv_prod_id:\t{:X?}
\tisv_svn:\t{:X?}
\tconfig_svn:\t{:X?}
\treserved4:\t{:X?}
\tisv_family_id:\t{:X?}
\treport_data:\t{:X?}\n",
            self.report_body.cpu_svn,
            self.report_body.misc_select,
            self.report_body.reserved1,
            self.report_body.isv_ext_prod_id,
            self.report_body.attributes.flags,
            self.report_body.attributes.xfrm,
            self.report_body.mr_enclave,
            self.report_body.reserved2,
            self.report_body.mr_signer,
            self.report_body.reserved3,
            self.report_body.config_id,
            self.report_body.isv_prod_id,
            self.report_body.isv_svn,
            self.report_body.config_svn,
            self.report_body.reserved4,
            self.report_body.isv_family_id,
            self.report_body.report_data,
        )?;

        write!(
            f,
            "
SIGNATURE
            
\tsignature_data_len:\t{:X?}
\tsignature_data:\t{:X?}\n",
            self.signature_data_len, self.signature_data
        )
    }
}
