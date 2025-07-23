use intel_tee_quote_verification_rs::quote3_error_t;

/// List of DCAP related errors.
/// <https://download.01.org/intel-sgx/sgx-dcap/1.23/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
pub(super) fn describe_error(error: quote3_error_t) -> String {
    let description = match error {
        quote3_error_t::TEE_SUCCESS => "Success.",
        quote3_error_t::SGX_QL_ERROR_UNEXPECTED => "An unexpected internal error occurred.",
        quote3_error_t::SGX_QL_ERROR_INVALID_PARAMETER => "The platform quote provider library rejected the input.",
        quote3_error_t::SGX_QL_ERROR_OUT_OF_MEMORY => "Heap memory allocation error in library or enclave.",
        quote3_error_t::SGX_QL_ERROR_ECDSA_ID_MISMATCH => "Expected ECDSA_ID does not match the value stored in the ECDSA Blob.",
        quote3_error_t::SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR => "The ECDSA blob pathname is too large.",
        quote3_error_t::SGX_QL_FILE_ACCESS_ERROR => "Not able to find the ‘label’ or there was a problem writing or retrieving the data.",
        quote3_error_t::SGX_QL_ERROR_STORED_KEY => "Cached ECDSA key is invalid.",
        quote3_error_t::SGX_QL_ERROR_PUB_KEY_ID_MISMATCH => "Cached ECDSA key does not match requested key.",
        quote3_error_t::SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME => " PCE use the incorrect signature scheme.",
        quote3_error_t::SGX_QL_ATT_KEY_BLOB_ERROR => "There is a problem with the attestation key blob.",
        quote3_error_t::SGX_QL_UNSUPPORTED_ATT_KEY_ID => "Unsupported attestation key ID.",
        quote3_error_t::SGX_QL_UNSUPPORTED_LOADING_POLICY => "Selected policy is not supported by the quoting library.",
        quote3_error_t::SGX_QL_INTERFACE_UNAVAILABLE => "Unable to load the PCE enclave.",
        quote3_error_t::SGX_QL_PLATFORM_LIB_UNAVAILABLE => "The Quote Verification Library could not locate the provider library.",
        quote3_error_t::SGX_QL_ATT_KEY_NOT_INITIALIZED => "Platform quoting infrastructure does not have the attestation key available to generate quotes.",
        quote3_error_t::SGX_QL_ATT_KEY_CERT_DATA_INVALID => "Certification data retrieved from the platform quote provider library is invalid.",
        quote3_error_t::SGX_QL_NO_PLATFORM_CERT_DATA => "The platform quote provider library doesn't have the platform certification data for this platform.",
        quote3_error_t::SGX_QL_OUT_OF_EPC => "Not enough memory in the EPC to load the enclave.",
        quote3_error_t::SGX_QL_ERROR_REPORT => "The QvE report can NOT be verified.",
        quote3_error_t::SGX_QL_ENCLAVE_LOST => "Enclave was lost after power transition or used in a child process created by linux:fork().",
        quote3_error_t::SGX_QL_INVALID_REPORT => "Report MAC check failed on an application report.",
        quote3_error_t::SGX_QL_ENCLAVE_LOAD_ERROR => "Unable to load one of the quote library enclaves required to initialize the attestation key. Could be due to file I/O error or some other loading infrastructure errors.",
        quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_QE_REPORT => "The QE was unable to generate its own report targeting the application enclave either because the QE doesn't support this feature there is an enclave compatibility issue.",
        quote3_error_t::SGX_QL_KEY_CERTIFCATION_ERROR => "Caused when the provider library returns an invalid TCB (too high).",
        quote3_error_t::SGX_QL_NETWORK_ERROR => "If the platform quote provider library uses the network to retrieve the QVE Identity, this error will be returned when it encounters network connectivity problems. Could be due to sgx_default_qcnl.conf wrong configuration.",
        quote3_error_t::SGX_QL_MESSAGE_ERROR => "If the platform quote provider library uses message protocols to retrieve the QVE Identity collateral, this error will be returned when it encounters any protocol problems.",
        quote3_error_t::SGX_QL_NO_QUOTE_COLLATERAL_DATA => "The platform quote provider library does not have the quote verification collateral data available.",
        quote3_error_t::SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED => "The quote verifier doesn’t support the certification data in the Quote. Currently, the Intel QVE only supported CertType = 5.",
        quote3_error_t::SGX_QL_QUOTE_FORMAT_UNSUPPORTED => "The inputted quote format is not supported. Either because the header information is not supported or the quote is malformed in some way.",
        quote3_error_t::SGX_QL_UNABLE_TO_GENERATE_REPORT => "The QVE was unable to generate its own report targeting the application enclave because there is an enclave compatibility issue.",
        quote3_error_t::SGX_QL_QE_REPORT_INVALID_SIGNATURE => "The signature over the QE Report is invalid.",
        quote3_error_t::SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT => "The quote verifier doesn’t support the format of the application REPORT the Quote.",
        quote3_error_t::SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT => "The format of the PCK certificate is unsupported.",
        quote3_error_t::SGX_QL_PCK_CERT_CHAIN_ERROR => "There was an error verifying the PCK certificate signature chain including PCK certificate revocation.",
        quote3_error_t::SGX_QL_TCBINFO_UNSUPPORTED_FORMAT => "The format of the TCBInfo structure is unsupported.",
        quote3_error_t::SGX_QL_TCBINFO_MISMATCH => "PCK certificate FMSPc does not match the TCBInfo FMSPc.",
        quote3_error_t::SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT => "The format of the QEIdentity structure is unsupported.",
        quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH => "The Quote’s QE doesn’t match the inputted expected QEIdentity.",
        quote3_error_t::SGX_QL_TCB_OUT_OF_DATE => "TCB out of date.",
        quote3_error_t::SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED => "TCB out of date and Configuration needed.",
        quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE => "SGX enclave identity out of date.",
        quote3_error_t::SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE => "SGX enclave report ISV SVN out of date.",
        quote3_error_t::SGX_QL_QE_IDENTITY_OUT_OF_DATE => "QE identity out of date.",
        quote3_error_t::SGX_QL_SGX_TCB_INFO_EXPIRED => "SGX TCB info expired.",
        quote3_error_t::SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED => "SGX PCK certificate chain expired.",
        quote3_error_t::SGX_QL_SGX_CRL_EXPIRED => "SGX CRL expired.",
        quote3_error_t::SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED => "SGX signing certificate chain expired.",
        quote3_error_t::SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED => "SGX enclave identity expired.",
        quote3_error_t::SGX_QL_PCK_REVOKED => "PCK is revoked.",
        quote3_error_t::SGX_QL_TCB_REVOKED => "TCB is revoked.",
        quote3_error_t::SGX_QL_TCB_CONFIGURATION_NEEDED => "TCB configuration needed.",
        quote3_error_t::SGX_QL_UNABLE_TO_GET_COLLATERAL => "Unable to get collateral.",
        quote3_error_t::SGX_QL_ERROR_INVALID_PRIVILEGE => "No enough privilege to perform the operation.",
        quote3_error_t::SGX_QL_NO_QVE_IDENTITY_DATA => "The platform quote provider library does not have the QVE identity data available.",
        quote3_error_t::SGX_QL_CRL_UNSUPPORTED_FORMAT => "Unsupported CRL format.",
        quote3_error_t::SGX_QL_QEIDENTITY_CHAIN_ERROR => "There was an error verifying the QEIdentity signature chain including QEIdentity revocation.",
        quote3_error_t::SGX_QL_TCBINFO_CHAIN_ERROR => "There was an error verifying the TCBInfo signature chain including TCBInfo revocation.",
        quote3_error_t::SGX_QL_ERROR_QVL_QVE_MISMATCH => "Only returned when the quote verification library supports both the untrusted mode of verification and the QvE backed mode of verification. This error indicates that the 2 versions of the verification modes are different. Most caused by using a QvE that does not match the version of the DCAP installed.",
        quote3_error_t::SGX_QL_TCB_SW_HARDENING_NEEDED => "TCB up to date but SW Hardening needed.",
        quote3_error_t::SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED => "TCB up to date but Configuration and SW Hardening needed.",
        quote3_error_t::SGX_QL_UNSUPPORTED_MODE => "The platform has been configured to use the out-of-process implementation of quote generation.",
        quote3_error_t::SGX_QL_NO_DEVICE => "Can't open SGX device. This error happens only when running in out-of-process mode.",
        quote3_error_t::SGX_QL_SERVICE_UNAVAILABLE => "Indicates AESM didn't respond or the requested service is not supported. This error happens only when running in out-of-process mode.",
        quote3_error_t::SGX_QL_NETWORK_FAILURE => "Network connection or proxy setting issue is encountered. This error happens only when running in out-of-process mode.",
        quote3_error_t::SGX_QL_SERVICE_TIMEOUT => "The request to out-of-process service has timed out. This error happens only when running in out-of-process mode.",
        quote3_error_t::SGX_QL_ERROR_BUSY => "The requested service is temporarily not available. This error happens only when running in out-of-process mode.",
        quote3_error_t::SGX_QL_UNKNOWN_MESSAGE_RESPONSE => "Unexpected error from the cache service.",
        quote3_error_t::SGX_QL_PERSISTENT_STORAGE_ERROR => "Error storing the retrieved cached data in persistent memory.",
        quote3_error_t::SGX_QL_ERROR_MESSAGE_PARSING_ERROR => "Generic message parsing error from the attestation infrastructure while retrieving the platform data.",
        quote3_error_t::SGX_QL_PLATFORM_UNKNOWN => "This platform is an unrecognized SGX platform.",
        quote3_error_t::SGX_QL_QVEIDENTITY_MISMATCH => "The QvE identity info from report doesn’t match to value in sgx_dcap_tvl.",
        quote3_error_t::SGX_QL_QVE_OUT_OF_DATE => "The input QvE ISV SVN threshold is smaller than actual QvE ISV SVN.",
        quote3_error_t::SGX_QL_PSW_NOT_AVAILABLE => "SGX PSW library cannot be loaded, could be due to file I/O error.",
        _ => "Unrecognized DCAP error code.",
    };

    format!("{:?} ({:#04x}) - {}", error, error as u32, description)
        .trim()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case(quote3_error_t::SGX_QL_QEIDENTITY_MISMATCH, "SGX_QL_QEIDENTITY_MISMATCH (0xe026) - The Quote’s QE doesn’t match the inputted expected QEIdentity.")]
    #[case(quote3_error_t::SGX_QL_SUCCESS, "SGX_QL_SUCCESS (0x00) - Success.")]
    fn describe_error_test(#[case] test_data: quote3_error_t, #[case] expected_result: &str) {
        let actual_result = describe_error(test_data);
        assert_eq!(actual_result, expected_result);
    }
}
