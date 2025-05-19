use super::*;

use self::serde::{Deserialize, Serialize};
use anyhow::anyhow;
use asn1_rs::{oid, FromDer, Integer, OctetString, Oid};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine};
use log::{debug, warn};
use openssl::{
    nid::Nid,
    x509::{self, X509},
};
use reqwest::{get, Response as ReqwestResponse, StatusCode};
use serde;
use serde_json::json;
use sev::{
    certs::snp::{ca::Chain as CaChain, Certificate, Chain, Verifiable},
    firmware::{
        guest::AttestationReport,
        host::{CertTableEntry, CertType},
    },
};
use std::{collections::HashMap, hash::Hash, result::Result::Ok, sync::LazyLock};
use strum::{Display, EnumIter, EnumString, IntoEnumIterator};
use x509_parser::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Option<Vec<CertTableEntry>>,
}

impl SnpEvidence {
    pub fn new(
        attestation_report: AttestationReport,
        cert_chain: Option<Vec<CertTableEntry>>,
    ) -> Self {
        Self {
            attestation_report,
            cert_chain,
        }
    }
}

pub(crate) const HW_ID_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
pub(crate) const UCODE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
pub(crate) const SNP_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
pub(crate) const TEE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
pub(crate) const LOADER_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);
pub(crate) const FMC_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .9);

// KDS URL parameters
const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
const KDS_VCEK: &str = "/vcek/v1";

/// Attestation report versions supported
const REPORT_VERSION_MIN: u32 = 3;
const REPORT_VERSION_MAX: u32 = 4;

pub(crate) static CERT_CHAINS: LazyLock<HashMap<ProcessorGeneration, VendorCertificates>> =
    LazyLock::new(|| {
        let mut map = HashMap::new();
        for proc in ProcessorGeneration::iter() {
            let cert_authority = match proc {
                ProcessorGeneration::Milan => include_bytes!("milan_ask_ark_asvk.pem"),
                ProcessorGeneration::Genoa => include_bytes!("genoa_ask_ark_asvk.pem"),
                ProcessorGeneration::Turin => include_bytes!("turin_ask_ark_asvk.pem"),
            };

            let certs = X509::stack_from_pem(cert_authority).unwrap();

            if certs.len() != 3 {
                panic!(
                    "Malformed cached Vendor Certs for {} processor (ASK, ARK, ASVK)",
                    proc
                );
            }

            let vendor_certs = VendorCertificates {
                ask: Certificate::from(certs[0].clone()),
                ark: Certificate::from(certs[1].clone()),
                asvk: Certificate::from(certs[2].clone()),
            };

            map.insert(proc, vendor_certs);
        }

        map
    });

#[derive(Default, Debug)]
pub struct Snp {}

#[derive(Clone, Debug)]
pub(crate) enum VendorEndorsementKey {
    Vcek,
    Vlek,
}

#[derive(Clone, Debug)]
pub(crate) struct VendorCertificates {
    pub(crate) ask: Certificate,
    pub(crate) ark: Certificate,
    pub(crate) asvk: Certificate,
}

#[derive(Debug, Clone, PartialEq, Eq, EnumString, Display, EnumIter, Hash)]
#[strum(serialize_all = "PascalCase", ascii_case_insensitive)]
pub(crate) enum ProcessorGeneration {
    /// 3rd Gen AMD EPYC Processor (Standard)
    Milan,

    /// 4th Gen AMD EPYC Processor (Standard)
    Genoa,

    /// 5th Gen AMD EPYC Processor (Standard)
    Turin,
}

#[async_trait]
impl Verifier for Snp {
    /// Evaluates the provided evidence against the expected report data and initialize data hash.
    /// Validates the report signature, version, VMPL, and other fields.
    /// Returns parsed claims if the verification is successful.
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let SnpEvidence {
            attestation_report: report,
            cert_chain,
        } = serde_json::from_slice(evidence).context("Deserialize SNP Evidence failed")?;

        // See Trustee Issue#589 https://github.com/confidential-containers/trustee/issues/589
        // Version 3 minimum is needed to tell processor type in report
        if report.version < REPORT_VERSION_MIN {
            bail!("Attestation Report version is too old. Please update your firmware.");
        } else if report.version > REPORT_VERSION_MAX {
            bail!("Unexpected attestation report version. Check SNP Firmware ABI specification");
        }

        // Get the processor model from the report
        let proc_gen: ProcessorGeneration = get_processor_generation(&report)?;

        // Get vendor certs for specific processor type
        let vendor_certs = CERT_CHAINS
            .get(&proc_gen)
            .ok_or_else(|| anyhow!("Vendor certs not found for processor type: {proc_gen:?}"))?;

        // Get the Version Endorsement Key (VEK) from the provided certs or KDS
        let vek = match cert_chain {
            // If the user provided cert chain, use that.
            Some(chain) => {
                // Initialize certs as options, will be filled out if left as none
                let mut ask: Option<Certificate> = None;
                let mut ark: Option<Certificate> = None;
                let mut vek: Option<Certificate> = None;
                let mut vek_type = VendorEndorsementKey::Vcek;

                // Iterate through the cert chain and find the ASK, ARK, and VCEK/VLEK
                for cert in chain.iter() {
                    match cert.cert_type {
                        CertType::ARK => {
                            // If the user provided ARK, verify against our trusted ARK
                            let provisioned_ark = vendor_certs.ark.clone();
                            ark = Some(Certificate::from_bytes(cert.data.as_slice())?);
                            (&provisioned_ark, &ark.clone().unwrap())
                                .verify()
                                .context("Provided ARK has an invalid signature")?;
                        }

                        CertType::ASK => {
                            ask = Some(Certificate::from_bytes(cert.data.as_slice())?);
                        }

                        // If both VLEK and VCEK are present, use the first one found
                        CertType::VCEK => {
                            if vek.is_none() {
                                vek = Some(Certificate::from_bytes(cert.data.as_slice())?);
                            }
                        }
                        CertType::VLEK => {
                            if vek.is_none() {
                                vek_type = VendorEndorsementKey::Vlek;
                                vek = Some(Certificate::from_bytes(cert.data.as_slice())?);
                            }
                        }
                        _ => continue,
                    }
                }

                let vek = vek.as_ref().ok_or_else(|| {
                    anyhow!("If a cert chain is provided, it must include a VCEK/VLEK")
                })?;

                // Make sure we have all the required certificates
                // Missing certs will be filled with the vendor certs
                let chain = Chain {
                    ca: CaChain {
                        ark: ark.unwrap_or_else(|| vendor_certs.ark.clone()),
                        ask: ask.unwrap_or_else(|| match vek_type {
                            VendorEndorsementKey::Vlek => vendor_certs.asvk.clone(),
                            VendorEndorsementKey::Vcek => vendor_certs.ask.clone(),
                        }),
                    },
                    vek: vek.clone(),
                };

                // Verify the chain and return vek if succesful
                chain
                    .verify()
                    .context("Certificate chain provided by user failed to verify")?;

                // Return the vek
                vek.clone()
            }

            // No certificate chain provided, so we need to request the VCEK from KDS
            _ => {
                // Get VCEK from KDS
                let vcek_buf = fetch_vcek_from_kds(report, proc_gen.clone())
                    .await
                    .context("Failed to fetch VCEK from KDS")?;
                let vcek = Certificate::from_bytes(&vcek_buf)
                    .context("Failed to convert KDS VCEK into certificate")?;

                let chain = Chain {
                    ca: CaChain {
                        ark: vendor_certs.ark.clone(),
                        ask: vendor_certs.ask.clone(),
                    },
                    vek: vcek.clone(),
                };

                // Verify the chain and return vek if succesful
                chain
                    .verify()
                    .context("Certificate chain from KDS failed verification")?;

                // Return the vcek
                vcek.clone()
            }
        };

        // Verify the report signature using the VEK
        (&vek, &report)
            .verify()
            .context("Report signature verification against VEK signature failed")?;

        // Verify the TCB values in the report against the VEK
        verify_report_tcb(&report, vek, proc_gen).context("Reported TCB values do not match")?;

        if report.vmpl != 0 {
            bail!("VMPL Check Failed");
        }

        // Verify expected data
        if let ReportData::Value(expected_report_data) = expected_report_data {
            debug!("Check the binding of REPORT_DATA.");
            let expected_report_data: Vec<u8> =
                regularize_data(expected_report_data, 64, "REPORT_DATA", "SNP");

            if expected_report_data != report.report_data.to_vec() {
                warn!(
                    "Report data mismatch. Given: {}, Expected: {}",
                    hex::encode(report.report_data),
                    hex::encode(expected_report_data)
                );
                bail!("Report Data Mismatch");
            }
        };

        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            debug!("Check the binding of HOST_DATA.");
            let expected_init_data_hash =
                regularize_data(expected_init_data_hash, 32, "HOST_DATA", "SNP");
            if expected_init_data_hash != report.host_data.to_vec() {
                bail!("Host Data Mismatch");
            }
        }

        let claims_map = parse_tee_evidence(&report);
        let json = json!(claims_map);
        Ok(json)
    }
}

/// Retrieves the octet string value for a given OID from a certificate's extensions.
/// Supports both raw and DER-encoded formats.
pub(crate) fn get_oid_octets<const N: usize>(
    vcek: &x509_parser::certificate::TbsCertificate,
    oid: Oid,
) -> Result<[u8; N]> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    // Previously, the hwID extension hasn't been encoded as DER octet string.
    // In this case, the value of the extension is the hwID itself (64 byte long),
    // and we can just return the value.
    if val.len() == N {
        return Ok(val.try_into().unwrap());
    }

    // Parse the value as DER encoded octet string.
    let (_, val_octet) = OctetString::from_der(val)?;
    val_octet
        .as_ref()
        .try_into()
        .context("Unexpected data size")
}

/// Retrieves an integer value for a given OID from a certificate's extensions.
pub(crate) fn get_oid_int(cert: &x509_parser::certificate::TbsCertificate, oid: Oid) -> Result<u8> {
    let val = cert
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    let (_, val_int) = Integer::from_der(val)?;
    val_int.as_u8().context("Unexpected data size")
}

/// Verifies the signature of the attestation report using the provided Vendor Endorsement Key (VEK).
pub(crate) fn verify_report_tcb(
    report: &AttestationReport,
    vek: Certificate,
    proc_gen: ProcessorGeneration,
) -> Result<()> {
    // OpenSSL bindings do not expose custom extensions
    // Parse the key using x509_parser
    let endorsement_key_der = vek.to_der()?;
    let parsed_endorsement_key = X509Certificate::from_der(&endorsement_key_der)?
        .1
        .tbs_certificate;

    let common_name =
        get_common_name(&vek.into()).context("No common name found in certificate")?;

    // if the common name is "VCEK", then the key is a VCEK
    // so lets check the chip id
    if common_name == "VCEK"
        && get_oid_octets::<64>(&parsed_endorsement_key, HW_ID_OID)? != *report.chip_id
    {
        bail!("Chip ID mismatch");
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_endorsement_key, UCODE_SPL_OID)? != report.reported_tcb.microcode {
        return Err(anyhow!("Microcode version mismatch"));
    }

    if get_oid_int(&parsed_endorsement_key, SNP_SPL_OID)? != report.reported_tcb.snp {
        return Err(anyhow!("SNP version mismatch"));
    }

    if get_oid_int(&parsed_endorsement_key, TEE_SPL_OID)? != report.reported_tcb.tee {
        return Err(anyhow!("TEE version mismatch"));
    }

    if get_oid_int(&parsed_endorsement_key, LOADER_SPL_OID)? != report.reported_tcb.bootloader {
        return Err(anyhow!("Boot loader version mismatch"));
    }

    // FMC is a Turin+ field only
    if proc_gen == ProcessorGeneration::Turin
        && get_oid_int(&parsed_endorsement_key, FMC_SPL_OID)? != report.reported_tcb.fmc.unwrap()
    {
        return Err(anyhow!("FMC version mismatch"));
    }

    Ok(())
}

/// Parses the attestation report and extracts the TEE evidence claims.
/// Returns a JSON-formatted map of parsed claims.
pub(crate) fn parse_tee_evidence(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", report.reported_tcb.bootloader),
        "reported_tcb_tee": format!("{}", report.reported_tcb.tee),
        "reported_tcb_snp": format!("{}", report.reported_tcb.snp),
        "reported_tcb_microcode": format!("{}", report.reported_tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurements
        "measurement": format!("{}", STANDARD.encode(report.measurement)),
        "report_data": format!("{}", STANDARD.encode(report.report_data)),
        "init_data": format!("{}", STANDARD.encode(report.host_data)),
    });

    claims_map as TeeEvidenceParsedClaim
}

/// Extracts the common name (CN) from the subject name of a certificate.
pub(crate) fn get_common_name(cert: &x509::X509) -> Result<String> {
    let mut entries = cert.subject_name().entries_by_nid(Nid::COMMONNAME);
    let Some(e) = entries.next() else {
        bail!("No CN found");
    };

    if entries.count() != 0 {
        bail!("No CN found");
    }

    Ok(e.data().as_utf8()?.to_string())
}

/// Asynchronously fetches the VCEK from the Key Distribution Service (KDS) using the provided attestation report.
/// Returns the VCEK in DER format as part of a certificate table entry.
async fn fetch_vcek_from_kds(
    att_report: AttestationReport,
    proc_gen: ProcessorGeneration,
) -> Result<Vec<u8>> {
    // Use attestation report to get data for URL
    let hw_id: String = if att_report.chip_id.as_slice() != [0; 64] {
        match proc_gen {
            ProcessorGeneration::Turin => {
                let shorter_bytes: &[u8] = &att_report.chip_id[0..8];
                hex::encode(shorter_bytes)
            }
            _ => hex::encode(att_report.chip_id),
        }
    } else {
        bail!("Hardware ID is 0s on attestation report. Confirm that MASK_CHIP_ID is set to 0 to request from VCEK from KDS.");
    };

    // Request VCEK from KDS
    let vcek_url: String = match proc_gen {
        ProcessorGeneration::Turin => {
            let fmc = if let Some(fmc) = att_report.reported_tcb.fmc {
                fmc
            } else {
                bail!("A Turin processor must have a fmc value");
            };
            format!(
                "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                {hw_id}?fmcSPL={:02}&blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                proc_gen,
                fmc,
                att_report.reported_tcb.bootloader,
                att_report.reported_tcb.tee,
                att_report.reported_tcb.snp,
                att_report.reported_tcb.microcode
            )
        }
        _ => {
            format!(
                "{KDS_CERT_SITE}{KDS_VCEK}/{}/\
                {hw_id}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                proc_gen,
                att_report.reported_tcb.bootloader,
                att_report.reported_tcb.tee,
                att_report.reported_tcb.snp,
                att_report.reported_tcb.microcode
            )
        }
    };
    // VCEK in DER format
    let vcek_rsp: ReqwestResponse = get(vcek_url.clone())
        .await
        .context("Unable to send request for VCEK")?;

    match vcek_rsp.status() {
        StatusCode::OK => {
            let vcek_rsp_bytes: Vec<u8> = vcek_rsp
                .bytes()
                .await
                .context("Unable to parse VCEK")?
                .to_vec();
            Ok(vcek_rsp_bytes)
        }

        status => bail!("Unable to fetch VCEK from URL: {status:?}, {vcek_url:?}"),
    }
}

/// Determines the processor model based on the family and model IDs from the attestation report.
fn get_processor_generation(att_report: &AttestationReport) -> Result<ProcessorGeneration> {
    let cpu_fam = att_report
        .cpuid_fam_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU family ID"))?;

    let cpu_mod = att_report
        .cpuid_mod_id
        .ok_or_else(|| anyhow::anyhow!("Attestation report version 3+ is missing CPU model ID"))?;

    match cpu_fam {
        0x19 => match cpu_mod {
            0x0..=0xF => Ok(ProcessorGeneration::Milan),
            0x10..=0x1F | 0xA0..0xAF => Ok(ProcessorGeneration::Genoa),
            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        0x1A => match cpu_mod {
            0x0..=0x11 => Ok(ProcessorGeneration::Turin),

            _ => Err(anyhow::anyhow!("Processor model not supported")),
        },
        _ => Err(anyhow::anyhow!("Processor family not supported")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VCEK: &[u8; 1360] = include_bytes!("../../test_data/snp/test-vcek.der");
    const VCEK_LEGACY: &[u8; 1361] =
        include_bytes!("../../test_data/snp/test-vcek-invalid-legacy.der");
    const VCEK_NEW: &[u8; 1362] = include_bytes!("../../test_data/snp/test-vcek-invalid-new.der");
    const VCEK_REPORT: &[u8; 1184] = include_bytes!("../../test_data/snp/test-report.bin");

    const VLEK: &[u8; 1319] = include_bytes!("../../test_data/snp/test-vlek.der");
    const VLEK_REPORT: &[u8; 1184] = include_bytes!("../../test_data/snp/test-vlek-report.bin");
    const DYNAMIC_EVIDENCE: &[u8; 6714] =
        include_bytes!("../../../../attestation-service/tests/e2e/evidence.json");

    #[test]
    fn check_milan_certificates() {
        let VendorCertificates { ask, ark, asvk } =
            CERT_CHAINS.get(&ProcessorGeneration::Milan).unwrap();
        assert_eq!(get_common_name(ark.into()).unwrap(), "ARK-Milan");
        assert_eq!(get_common_name(ask.into()).unwrap(), "SEV-Milan");
        assert_eq!(get_common_name(asvk.into()).unwrap(), "SEV-VLEK-Milan");

        (ark, ark)
            .verify()
            .context("Invalid ARK Signature")
            .unwrap();

        (ark, ask)
            .verify()
            .context("Invalid ASK Signature")
            .unwrap();

        (ark, asvk)
            .verify()
            .context("Invalid ASVK Signature")
            .unwrap();
    }

    #[test]
    fn check_genoa_certificates() {
        let VendorCertificates { ask, ark, asvk } =
            CERT_CHAINS.get(&ProcessorGeneration::Genoa).unwrap();
        assert_eq!(get_common_name(ark.into()).unwrap(), "ARK-Genoa");
        assert_eq!(get_common_name(ask.into()).unwrap(), "SEV-Genoa");
        assert_eq!(get_common_name(asvk.into()).unwrap(), "SEV-VLEK-Genoa");

        (ark, ark)
            .verify()
            .context("Invalid ARK Signature")
            .unwrap();

        (ark, ask)
            .verify()
            .context("Invalid ASK Signature")
            .unwrap();

        (ark, asvk)
            .verify()
            .context("Invalid ASVK Signature")
            .unwrap();
    }

    #[test]
    fn check_turin_certificates() {
        let VendorCertificates { ask, ark, asvk } =
            CERT_CHAINS.get(&ProcessorGeneration::Turin).unwrap();
        assert_eq!(get_common_name(ark.into()).unwrap(), "ARK-Turin");
        assert_eq!(get_common_name(ask.into()).unwrap(), "SEV-Turin");
        assert_eq!(get_common_name(asvk.into()).unwrap(), "SEV-VLEK-Turin");

        (ark, ark)
            .verify()
            .context("Invalid ARK Signature")
            .unwrap();

        (ark, ask)
            .verify()
            .context("Invalid ASK Signature")
            .unwrap();

        (ark, asvk)
            .verify()
            .context("Invalid ASVK Signature")
            .unwrap();
    }

    fn check_oid_ints(cert: &TbsCertificate) {
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(cert, oid).unwrap();
        }
    }

    #[test]
    fn check_vlek_parsing() {
        let parsed_vlek = X509Certificate::from_der(VLEK).unwrap().1.tbs_certificate;

        check_oid_ints(&parsed_vlek);
    }

    #[test]
    fn check_vcek_parsing() {
        let parsed_vcek = X509Certificate::from_der(VCEK).unwrap().1.tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();

        check_oid_ints(&parsed_vcek);
    }

    #[test]
    fn check_vcek_parsing_legacy() {
        let parsed_vcek = X509Certificate::from_der(VCEK_LEGACY)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();

        check_oid_ints(&parsed_vcek);
    }

    #[test]
    fn check_vcek_parsing_new() {
        let parsed_vcek = X509Certificate::from_der(VCEK_NEW)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();

        check_oid_ints(&parsed_vcek);
    }

    #[test]
    fn check_vcek_signature_verification() {
        let vcek = Certificate::from_bytes(VCEK).unwrap();

        let VendorCertificates { ask, ark, asvk: _ } =
            CERT_CHAINS.get(&ProcessorGeneration::Milan).unwrap();
        let chain = Chain {
            ca: CaChain {
                ark: ark.clone(),
                ask: ask.clone(),
            },
            vek: vcek.clone(),
        };
        chain.verify().unwrap();
    }

    #[test]
    fn check_vcek_signature_failure() {
        let mut vcek_bytes = *VCEK;

        // corrupt some byte, while it should remain a valid cert
        vcek_bytes[42] += 1;
        let vcek = Certificate::from_bytes(&vcek_bytes).unwrap();
        let VendorCertificates { ask, ark, asvk: _ } =
            CERT_CHAINS.get(&ProcessorGeneration::Milan).unwrap();
        let chain = Chain {
            ca: CaChain {
                ark: ark.clone(),
                ask: ask.clone(),
            },
            vek: vcek.clone(),
        };

        chain.verify().unwrap_err();
    }

    #[test]
    fn check_vlek_signature_verification() {
        let vlek = Certificate::from_bytes(VLEK).unwrap();

        let VendorCertificates { ask: _, ark, asvk } =
            CERT_CHAINS.get(&ProcessorGeneration::Milan).unwrap();
        let chain = Chain {
            ca: CaChain {
                ark: ark.clone(),
                ask: asvk.clone(),
            },
            vek: vlek.clone(),
        };
        chain.verify().unwrap();
    }

    #[test]
    fn check_vlek_signature_failure() {
        let mut vlek_bytes = *VCEK;

        // corrupt some byte, while it should remain a valid cert
        vlek_bytes[42] += 1;

        let vlek = Certificate::from_bytes(&vlek_bytes).unwrap();
        let VendorCertificates { ask: _, ark, asvk } =
            CERT_CHAINS.get(&ProcessorGeneration::Milan).unwrap();
        let chain = Chain {
            ca: CaChain {
                ark: ark.clone(),
                ask: asvk.clone(),
            },
            vek: vlek.clone(),
        };
        chain.verify().unwrap_err();
    }

    #[test]
    fn check_milan_chain_signature_failure() {
        let vcek = Certificate::from_bytes(VCEK).unwrap();
        let VendorCertificates { ask: _, ark, asvk } =
            CERT_CHAINS.get(&ProcessorGeneration::Milan).unwrap();

        // toggle ark <=> ask
        let chain = Chain {
            ca: CaChain {
                ark: ark.clone(),
                ask: asvk.clone(),
            },
            vek: vcek.clone(),
        };
        chain.verify().unwrap_err();
    }

    #[test]
    fn check_report_signature() {
        let attestation_report = AttestationReport::from_bytes(VCEK_REPORT).unwrap();
        let vcek = Certificate::from_bytes(VCEK).unwrap();
        (&vcek, &attestation_report).verify().unwrap();
        verify_report_tcb(&attestation_report, vcek, ProcessorGeneration::Milan).unwrap();
    }

    #[test]
    fn check_vlek_report_signature() {
        let attestation_report = AttestationReport::from_bytes(VLEK_REPORT).unwrap();
        let vlek = Certificate::from_bytes(VLEK).unwrap();
        (&vlek, &attestation_report).verify().unwrap();
        verify_report_tcb(&attestation_report, vlek, ProcessorGeneration::Milan).unwrap();
    }

    #[test]
    fn check_report_signature_failure() {
        let mut bytes = *VCEK_REPORT;

        // corrupt some byte
        bytes[42] += 1;

        let attestation_report = AttestationReport::from_bytes(&bytes).unwrap();
        let vcek = Certificate::from_bytes(VCEK).unwrap();
        (&vcek, &attestation_report).verify().unwrap_err();
    }

    #[test]
    fn check_report_tcb_failure() {
        let mut bytes = *VCEK_REPORT;

        // corrupt some byte
        bytes[384] += 1;

        let attestation_report = AttestationReport::from_bytes(&bytes).unwrap();
        let vcek = Certificate::from_bytes(VCEK).unwrap();
        verify_report_tcb(&attestation_report, vcek, ProcessorGeneration::Milan).unwrap_err();
    }

    #[test]
    fn check_vlek_report_signature_failure() {
        let mut bytes = *VLEK_REPORT;

        // corrupt some byte
        bytes[42] += 1;

        let attestation_report = AttestationReport::from_bytes(&bytes).unwrap();
        let vlek = Certificate::from_bytes(VLEK).unwrap();
        (&vlek, &attestation_report).verify().unwrap_err();
    }

    #[test]
    fn check_vlek_report_tcb_failure() {
        let mut bytes = *VLEK_REPORT;

        // corrupt some byte
        bytes[384] += 1;

        let attestation_report = AttestationReport::from_bytes(&bytes).unwrap();
        let vlek = Certificate::from_bytes(VLEK).unwrap();
        verify_report_tcb(&attestation_report, vlek, ProcessorGeneration::Milan).unwrap_err();
    }

    #[test]
    fn check_json_deserialize_report() {
        let attestation_report = AttestationReport::from_bytes(VCEK_REPORT).unwrap();
        let json_string = serde_json::to_string(&attestation_report).unwrap();
        let deserialized_report: AttestationReport =
            serde_json::from_str(&json_string).expect("Failed to deserialize JSON");
        assert_eq!(attestation_report, deserialized_report);
    }

    #[test]
    fn test_dynamic_evidence() {
        let SnpEvidence {
            attestation_report: report,
            cert_chain,
        } = serde_json::from_slice(DYNAMIC_EVIDENCE)
            .context("Deserialize SNP Evidence failed")
            .unwrap();

        let vcek: Certificate = if let Some(chain) = cert_chain {
            Certificate::from_bytes(chain[0].data.as_slice()).unwrap()
        } else {
            unreachable!("Test evidence should always have a cert chain")
        };

        (&vcek, &report)
            .verify()
            .context("Report signature verification against VEK signature failed")
            .unwrap();
    }
}
