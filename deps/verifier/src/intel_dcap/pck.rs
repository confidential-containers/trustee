// Copyright (c) 2026 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0
//

//! Parsing of Intel SGX extensions from PCK (Provisioning Certification Key)
//! certificates. The extensions are DER-encoded under OID 1.2.840.113741.1.13.1
//! and are present in both TDX and SGX PCK certificate chains.
//! See "Intel® SGX PCK Certificate and Certificate Revocation List Profile Specification".

use anyhow::{anyhow, bail, Context, Result};
use asn1_rs::{oid, DerSequence, Enumerated, FromDer, Oid};
use x509_parser::prelude::*;

const DCAP_SGX_EXTENSIONS: Oid<'static> = oid!(1.2.840 .113741 .1 .13 .1);
const PCK_PLATFORM_CA_CN: &str = "Intel SGX PCK Platform CA";
const PCK_PROCESSOR_CA_CN: &str = "Intel SGX PCK Processor CA";

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndString<'a> {
    id: Oid<'a>,
    s: &'a [u8],
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndInt<'a> {
    id: Oid<'a>,
    val: u8,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndInt16<'a> {
    id: Oid<'a>,
    val: u16,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndEnum<'a> {
    id: Oid<'a>,
    e: Enumerated,
}

#[derive(Debug, PartialEq, DerSequence)]
struct OidAndBool<'a> {
    id: Oid<'a>,
    b: bool,
}

#[derive(Debug, PartialEq, DerSequence)]
struct PlatformConfig<'a> {
    dynamic_platform: OidAndBool<'a>,
    cached_keys: OidAndBool<'a>,
    smt_enabled: OidAndBool<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct ConfigSequence<'a> {
    id: Oid<'a>,
    configs: PlatformConfig<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct Tcbs<'a> {
    comp1: OidAndInt<'a>,
    comp2: OidAndInt<'a>,
    comp3: OidAndInt<'a>,
    comp4: OidAndInt<'a>,
    comp5: OidAndInt<'a>,
    comp6: OidAndInt<'a>,
    comp7: OidAndInt<'a>,
    comp8: OidAndInt<'a>,
    comp9: OidAndInt<'a>,
    comp10: OidAndInt<'a>,
    comp11: OidAndInt<'a>,
    comp12: OidAndInt<'a>,
    comp13: OidAndInt<'a>,
    comp14: OidAndInt<'a>,
    comp15: OidAndInt<'a>,
    comp16: OidAndInt<'a>,
    pcesvn: OidAndInt16<'a>,
    cpusvn: OidAndString<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct TcbSequence<'a> {
    id: Oid<'a>,
    tcbs: Tcbs<'a>,
}

#[derive(Debug, PartialEq, DerSequence)]
struct SgxExtension<'a> {
    ppid: OidAndString<'a>,
    tcb: TcbSequence<'a>,
    pceid: OidAndString<'a>,
    fmspc: OidAndString<'a>,
    sgxtype: OidAndEnum<'a>,
    /// Absent in Processor CA-signed certs.
    platform_instance: Option<OidAndString<'a>>,
    /// Absent in Processor CA-signed certs.
    configuration: Option<ConfigSequence<'a>>,
}

/// Owned platform information extracted from the SGX extensions of a PCK certificate chain.
///
/// SGX extensions are DER-encoded under OID 1.2.840.113741.1.13.1 and present in
/// both TDX and SGX PCK certificate chains.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlatformInfo {
    /// FMSPC (Family-Model-Stepping-Platform-CustomSKU) identifier.
    pub fmspc: [u8; 6],
    /// PCE (Provisioning Certification Enclave) identifier.
    pub pceid: [u8; 2],
    /// 16 SGX TCB SVN components.
    pub tcb_components: [u8; 16],
    /// PCE security version number.
    pub pcesvn: u16,
    /// CPU security version number.
    pub cpusvn: [u8; 16],
    /// SGX type: 0 = Standard, 1 = Scalable, 2 = ScalableWithIntegrity.
    pub sgx_type: u8,
    /// `true` for Platform CA-signed certs, `false` for Processor CA-signed certs.
    pub is_platform_ca: bool,
    /// Present only in Platform CA-signed certs; `None` for Processor CA-signed certs.
    pub platform_instance_id: Option<[u8; 16]>,
    /// Present only in Platform CA-signed certs; `None` for Processor CA-signed certs.
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

/// A parsed PCK certificate chain with named positions.
/// The Intel cert chain ordering is leaf (index 0), intermediate CA, root CA.
struct PckCertificateChain {
    leaf: Pem,
    intermediate: Pem,
    _root: Pem,
}

/// Parse all PEM-encoded certificates from a PCK certificate chain.
fn parse_pck_pem_certs(pem_certs: &[u8]) -> Result<PckCertificateChain> {
    let [leaf, intermediate, root] = Pem::iter_from_buffer(pem_certs)
        .collect::<Result<Vec<Pem>, _>>()
        .context("failed to parse PCK PEM certificate chain")
        .and_then(|pems| {
            pems.try_into().map_err(|v: Vec<Pem>| {
                anyhow!(
                    "PCK cert chain must contain exactly 3 certificates (leaf, intermediate CA, root CA), got {}",
                    v.len()
                )
            })
        })?;

    Ok(PckCertificateChain {
        leaf,
        intermediate,
        _root: root,
    })
}

/// Parse the SGX extensions from a PCK certificate chain and return owned platform information.
///
/// The CA type is derived from the intermediate cert subject CN, which also determines
/// which SGX extension fields are present. Absent SGX extensions is an error — PCK
/// leaf certificates are always expected to carry them.
pub(crate) fn parse_platform_info(pem_certs: &[u8]) -> Result<PlatformInfo> {
    let chain = parse_pck_pem_certs(pem_certs)?;

    let intermediate = chain
        .intermediate
        .parse_x509()
        .context("failed to parse PCK intermediate CA cert")?;

    let is_platform_ca = intermediate
        .subject()
        .iter_common_name()
        .next()
        .context("PCK intermediate CA cert has no Common Name")?
        .as_str()
        .context("PCK intermediate CA CN is not valid UTF-8")
        .and_then(|cn| match cn {
            PCK_PLATFORM_CA_CN => Ok(true),
            PCK_PROCESSOR_CA_CN => Ok(false),
            other => bail!("unexpected PCK intermediate CA CN: {other}"),
        })?;

    let leaf = chain
        .leaf
        .parse_x509()
        .context("failed to parse PCK leaf cert")?;

    let ext = leaf
        .tbs_certificate
        .get_extension_unique(&DCAP_SGX_EXTENSIONS)
        .context("failed to look up SGX extensions OID")?
        .context("SGX extensions OID not found in PCK leaf cert")?;

    let (rem, sgx) =
        SgxExtension::from_der(ext.value).context("failed to parse SGX extension DER")?;

    if !rem.is_empty() {
        bail!("SGX extension has {} unexpected trailing bytes", rem.len());
    }

    let tcb = &sgx.tcb.tcbs;

    let fmspc: [u8; 6] = sgx.fmspc.s.try_into().context("fmspc is not 6 bytes")?;
    let pceid: [u8; 2] = sgx.pceid.s.try_into().context("pceid is not 2 bytes")?;

    let tcb_components = [
        tcb.comp1.val,
        tcb.comp2.val,
        tcb.comp3.val,
        tcb.comp4.val,
        tcb.comp5.val,
        tcb.comp6.val,
        tcb.comp7.val,
        tcb.comp8.val,
        tcb.comp9.val,
        tcb.comp10.val,
        tcb.comp11.val,
        tcb.comp12.val,
        tcb.comp13.val,
        tcb.comp14.val,
        tcb.comp15.val,
        tcb.comp16.val,
    ];

    let cpusvn: [u8; 16] = tcb.cpusvn.s.try_into().context("cpusvn is not 16 bytes")?;
    let sgx_type = sgx.sgxtype.e.0 as u8;

    // Cross-check: the CA type from the intermediate cert must agree with the presence
    // of platform_instance and configuration in the leaf cert's SGX extensions.
    let (platform_instance_id, dynamic_platform, cached_keys, smt_enabled) = match is_platform_ca {
        true => {
            let pi = sgx
                .platform_instance
                .as_ref()
                .context("Platform PCK cert is missing platform_instance")?;

            let cfg_seq = sgx
                .configuration
                .as_ref()
                .context("Platform PCK cert is missing configuration")?;

            let cfg = &cfg_seq.configs;

            let bytes: [u8; 16] =
                pi.s.try_into()
                    .context("platform_instance is not 16 bytes")?;

            // The GUID is stored little-endian in the OCTET STRING; convert to big-endian.
            let piid = u128::from_le_bytes(bytes).to_be_bytes();

            (
                Some(piid),
                Some(cfg.dynamic_platform.b),
                Some(cfg.cached_keys.b),
                Some(cfg.smt_enabled.b),
            )
        }
        false => {
            if sgx.platform_instance.is_some() || sgx.configuration.is_some() {
                bail!("Processor CA cert unexpectedly contains platform_instance or configuration");
            }
            (None, None, None, None)
        }
    };

    Ok(PlatformInfo {
        fmspc,
        pceid,
        tcb_components,
        pcesvn: tcb.pcesvn.val,
        cpusvn,
        sgx_type,
        is_platform_ca,
        platform_instance_id,
        dynamic_platform,
        cached_keys,
        smt_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::parse_platform_info;
    use crate::intel_dcap::quote::parse_quote;

    #[test]
    fn parse_platform_info_platform_ca() {
        let quote_bin = std::fs::read("./test_data/tdx_quote_4.dat").expect("read quote failed");
        let quote = parse_quote(&quote_bin).expect("parse quote");

        let info = parse_platform_info(&quote.cert_data().qe_certification_data.certificates)
            .expect("parse platform info");

        assert!(info.is_platform_ca);
        assert_eq!(
            hex::encode(
                info.platform_instance_id
                    .expect("platform_instance_id not present")
            ),
            "82548d228d94d5e204a95b354dc61a02"
        );
        assert_eq!(info.fmspc.len(), 6);
        assert_eq!(info.pceid.len(), 2);
        assert!(info.dynamic_platform.is_some());
        assert!(info.cached_keys.is_some());
        assert!(info.smt_enabled.is_some());
    }
}
