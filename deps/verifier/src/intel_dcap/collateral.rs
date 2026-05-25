// Copyright (c) 2026 Intel Corporation.
//
// SPDX-License-Identifier: Apache-2.0

//! Fetch verification collateral from a `CollateralService` and assemble it
//! into a `QuoteCollateral` for use with `tee_verify_quote`.

use anyhow::{anyhow, bail, Context, Result};
use asn1_rs::{oid, Oid};
use intel_tee_quote_verification_rs::QuoteCollateral;
use std::os::raw::c_char;
use x509_parser::prelude::*;

use super::collateral_service::{
    CollateralData, CollateralService, CollateralType, IntelTee, PckCaType,
};

const CRL_DISTRIBUTION_POINTS: Oid<'static> = oid!(2.5.29 .31);

fn to_c_str(bytes: Vec<u8>) -> Vec<c_char> {
    let mut v: Vec<c_char> = bytes.into_iter().map(|b| b as c_char).collect();
    v.push(0);
    v
}

/// Extract the Root CA CRL distribution point URL from the Root CA certificate.
///
/// The Root CA is the last certificate in the PEM-encoded issuer chain returned
/// with the QE Identity response. Its CRL Distribution Points extension contains
/// the URL from which the Root CA's CRL can be fetched.
fn root_ca_crl_distpoint(cert_chain_pem: &[u8]) -> Result<String> {
    let pems: Vec<Pem> = Pem::iter_from_buffer(cert_chain_pem)
        .collect::<Result<_, _>>()
        .context("failed to parse QE Identity issuer chain")?;

    let last = pems.last().context("QE Identity issuer chain is empty")?;

    let cert = last.parse_x509().context("failed to parse root CA cert")?;

    let ext = cert
        .get_extension_unique(&CRL_DISTRIBUTION_POINTS)
        .map_err(|_| anyhow!("duplicate CRL Distribution Points extensions"))?
        .context("root CA cert has no CRL Distribution Points extension")?;

    if let ParsedExtension::CRLDistributionPoints(cdps) = ext.parsed_extension() {
        for dp in cdps.iter() {
            if let Some(DistributionPointName::FullName(gns)) = &dp.distribution_point {
                for gn in gns {
                    if let GeneralName::URI(uri) = gn {
                        return Ok((*uri).to_string());
                    }
                }
            }
        }
    }

    bail!("no URI found in CRL Distribution Points of root CA cert")
}

/// Fetch all verification collateral from PCS and return a [`QuoteCollateral`]
/// ready for use with `tee_verify_quote`.
///
/// The Root CA CRL distribution point URL is read from the Root CA certificate,
/// which is the last certificate in the QE Identity issuer chain.
pub(crate) async fn build_quote_collateral(
    fmspc: [u8; 6],
    is_platform_ca: bool,
    tee_type: [u8; 4],
    cs: &impl CollateralService,
) -> Result<QuoteCollateral> {
    let tee = match u32::from_le_bytes(tee_type) {
        0x00000000 => IntelTee::Sgx,
        0x00000081 => IntelTee::Tdx,
        t => bail!("unsupported tee_type {t:#010x}"),
    };

    let CollateralData {
        body: tcb_info,
        cert_chain: tcb_chain,
    } = cs
        .get(CollateralType::TcbInfo(&tee, fmspc))
        .await
        .context("failed to fetch TcbInfo")?;

    let CollateralData {
        body: qe_identity,
        cert_chain: qe_chain,
    } = cs
        .get(CollateralType::QeIdentity(&tee))
        .await
        .context("failed to fetch QeIdentity")?;

    let qe_chain = qe_chain.context("QE Identity response missing issuer chain")?;

    let root_ca_crl_url = root_ca_crl_distpoint(&qe_chain)
        .context("failed to read Root CA CRL distribution point from QE Identity issuer chain")?;

    let pck_ca = if is_platform_ca {
        PckCaType::Platform
    } else {
        PckCaType::Processor
    };

    let CollateralData {
        body: pck_crl,
        cert_chain: pck_crl_chain,
    } = cs
        .get(CollateralType::PckCrl(pck_ca))
        .await
        .context("failed to fetch PCK CRL")?;

    let CollateralData {
        body: root_ca_crl,
        cert_chain: _,
    } = cs
        .get(CollateralType::RootCaCrl(Some(&root_ca_crl_url)))
        .await
        .context("failed to fetch Root CA CRL")?;

    Ok(QuoteCollateral {
        // major_version = 3, minor_version = 1: CRLs are raw binary DER.
        major_version: 3,
        minor_version: 1,
        tee_type: u32::from_le_bytes(tee_type),
        tcb_info: to_c_str(tcb_info),
        tcb_info_issuer_chain: to_c_str(
            tcb_chain.context("TcbInfo response missing issuer chain")?,
        ),
        qe_identity: to_c_str(qe_identity),
        qe_identity_issuer_chain: to_c_str(qe_chain),
        pck_crl: to_c_str(pck_crl),
        pck_crl_issuer_chain: to_c_str(
            pck_crl_chain.context("PCK CRL response missing issuer chain")?,
        ),
        root_ca_crl: to_c_str(root_ca_crl),
    })
}
