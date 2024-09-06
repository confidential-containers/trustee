project(
  'sgx_dcap_quoteverify_stubs', 'cpp',
  default_options: ['warning_level=3'],
)

stub_headers = files([
  'sgx_attributes.h',
  'sgx_dcap_qal.h',
  'sgx_dcap_quoteverify.h',
  'sgx_defs.h',
  'sgx_eid.h',
  'sgx_error.h',
  'sgx_key.h',
  'sgx_pce.h',
  'sgx_ql_lib_common.h',
  'sgx_ql_quote.h',
  'sgx_quote.h',
  'sgx_quote_3.h',
  'sgx_quote_4.h',
  'sgx_quote_5.h',
  'sgx_qve_header.h',
  'sgx_report.h',
  'sgx_report2.h',
  'sgx_urts.h',
])

install_headers(stub_headers)

extra_args = [
  '-Werror',
  '-Wno-pedantic',
  '-Wno-padded',
]

library(
  'sgx_dcap_quoteverify',
  'sgx_dcap_quoteverify_stub.cpp',
  cpp_args: extra_args,
  soversion: '1',
  install: true,
)
