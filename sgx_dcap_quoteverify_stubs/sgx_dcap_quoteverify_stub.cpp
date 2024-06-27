/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /**
  * File: sgx_dcap_quoteverify.cpp
  *
  * Description: Quote Verification Library
  */

#include <iostream>
#include "sgx_dcap_quoteverify.h"

quote3_error_t sgx_qv_set_enclave_load_policy(
    sgx_ql_request_policy_t policy __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Get supplemental data latest version and required size.
 **/
quote3_error_t tee_get_supplemental_data_version_and_size(
    const uint8_t *p_quote __attribute__((unused)),
    uint32_t quote_size __attribute__((unused)),
    uint32_t *p_version __attribute__((unused)),
    uint32_t *p_data_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Get SGX QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_get_qve_identity(
         uint8_t **pp_qveid __attribute__((unused)),
         uint32_t *p_qveid_size __attribute__((unused)),
         uint8_t **pp_qveid_issue_chain __attribute__((unused)),
         uint32_t *p_qveid_issue_chain_size __attribute__((unused)),
         uint8_t **pp_root_ca_crl __attribute__((unused)),
         uint16_t *p_root_ca_crl_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}


/**
 * Free SGX QvE identity and Root CA CRL
 **/
quote3_error_t sgx_qv_free_qve_identity(
        uint8_t *p_qveid __attribute__((unused)),
        uint8_t *p_qveid_issue_chain __attribute__((unused)),
        uint8_t *p_root_ca_crl __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Get SGX supplemental data required size.
 **/
quote3_error_t sgx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Perform SGX ECDSA quote verification
 **/
quote3_error_t sgx_qv_verify_quote(
    const uint8_t *p_quote __attribute__((unused)),
    uint32_t quote_size __attribute__((unused)),
    const sgx_ql_qve_collateral_t *p_quote_collateral __attribute__((unused)),
    const time_t expiration_check_date __attribute__((unused)),
    uint32_t *p_collateral_expiration_status __attribute__((unused)),
    sgx_ql_qv_result_t *p_quote_verification_result __attribute__((unused)),
    sgx_ql_qe_report_info_t *p_qve_report_info __attribute__((unused)),
    uint32_t supplemental_data_size __attribute__((unused)),
    uint8_t *p_supplemental_data __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Get TDX supplemental data required size.
 **/
quote3_error_t tdx_qv_get_quote_supplemental_data_size(uint32_t *p_data_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Perform TDX ECDSA quote verification
 **/
quote3_error_t tdx_qv_verify_quote(
    const uint8_t *p_quote __attribute__((unused)),
    uint32_t quote_size __attribute__((unused)),
    const tdx_ql_qv_collateral_t *p_quote_collateral __attribute__((unused)),
    const time_t expiration_check_date __attribute__((unused)),
    uint32_t *p_collateral_expiration_status __attribute__((unused)),
    sgx_ql_qv_result_t *p_quote_verification_result __attribute__((unused)),
    sgx_ql_qe_report_info_t *p_qve_report_info __attribute__((unused)),
    uint32_t supplemental_data_size __attribute__((unused)),
    uint8_t *p_supplemental_data __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * @brief retrieve verification colloateral
 *
 */
quote3_error_t tee_qv_get_collateral(
    const uint8_t *p_quote __attribute__((unused)),
    uint32_t quote_size __attribute__((unused)),
    uint8_t **pp_quote_collateral __attribute__((unused)),
    uint32_t *p_collateral_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * @brief free verification colloateral
 *
 */
quote3_error_t tee_qv_free_collateral(uint8_t *p_quote_collateral __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * Perform quote verification for SGX and TDX
 * This API works the same as the old one __attribute__((unused)), but takes a new parameter to describe the supplemental data (p_supp_data_descriptor)
 **/
quote3_error_t tee_verify_quote(
    const uint8_t *p_quote __attribute__((unused)),
    uint32_t quote_size __attribute__((unused)),
    const uint8_t *p_quote_collateral __attribute__((unused)),
    const time_t expiration_check_date __attribute__((unused)),
    uint32_t *p_collateral_expiration_status __attribute__((unused)),
    sgx_ql_qv_result_t *p_quote_verification_result __attribute__((unused)),
    sgx_ql_qe_report_info_t *p_qve_report_info __attribute__((unused)),
    tee_supp_data_descriptor_t *p_supp_data_descriptor __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

/**
 * @brief Extrace FMSPC from a given quote with cert type 5
 * @param p_quote[IN] - Pointer to a quote buffer.
 * @param quote_size[IN] - Size of input quote buffer.
 * @param p_fmspc_from_quote[IN/OUT] - Pointer to a buffer to write fmspc to.
 * @param fmspc_from_quote_size[IN] - Size of fmspc buffer.
 *
 * @return Status code of the operation __attribute__((unused)), one of:
 *      - SGX_QL_SUCCESS
 *      - SGX_QL_ERROR_INVALID_PARAMETER
 *      - SGX_QL_ERROR_UNEXPECTED
 *      - SGX_QL_PCK_CERT_CHAIN_ERROR
 *      - SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED
 */
quote3_error_t tee_get_fmspc_from_quote(const uint8_t *p_quote __attribute__((unused)),
                                        uint32_t quote_size __attribute__((unused)),
                                        uint8_t *p_fmspc_from_quote __attribute__((unused)),
                                        uint32_t fmspc_from_quote_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}


/**
 * This API can be used to set the full path of QVE and QPL library.
 *
 * The function takes the enum and the corresponding full path.
 *
 * @param path_type The type of binary being passed in.
 * @param p_path It should be a valid full path.
 *
 * @return SGX_QL_SUCCESS  Successfully set the full path.
 * @return SGX_QL_ERROR_INVALID_PARAMETER p_path is not a valid full path or the path is too long.
 */

quote3_error_t sgx_qv_set_path(
        sgx_qv_path_type_t path_type __attribute__((unused)),
        const char *p_path __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

quote3_error_t  tee_verify_quote_qvt(
    const uint8_t *p_quote __attribute__((unused)),
    uint32_t quote_size __attribute__((unused)),
    const sgx_ql_qve_collateral_t *p_quote_collateral __attribute__((unused)),
    sgx_ql_qe_report_info_t *p_qve_report_info __attribute__((unused)),
    const uint8_t *p_user_data __attribute__((unused)),
    uint32_t *p_verification_result_token_buffer_size __attribute__((unused)),
    uint8_t **p_verification_result_token __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}

quote3_error_t tee_free_verify_quote_qvt(
    uint8_t *p_verification_result_token __attribute__((unused)),
    uint32_t *p_verification_result_token_buffer_size __attribute__((unused)))
{
    std::cout << "Not implemented" << std::endl;
    return SGX_QL_ERROR_UNEXPECTED;
}
