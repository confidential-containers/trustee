use anyhow::anyhow;
use base64::Engine;
use log::debug;
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use asn1_rs::{oid, Integer, OctetString, Oid};
use async_trait::async_trait;
use openssl::{
    ec::EcKey,
    ecdsa,
    pkey::{PKey, Public},
    sha::sha384,
    x509::{self, X509},
};
use serde_json::json;
use sev::firmware::guest::AttestationReport;
use sev::firmware::host::{CertTableEntry, CertType};
use std::sync::OnceLock;
use x509_parser::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Vec<CertTableEntry>,
}

const HW_ID_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
const UCODE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
const SNP_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
const TEE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
const LOADER_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);

#[derive(Debug)]
pub struct Snp {
    vendor_certs: VendorCertificates,
}

pub(crate) fn load_milan_cert_chain() -> &'static Result<VendorCertificates> {
    static MILAN_CERT_CHAIN: OnceLock<Result<VendorCertificates>> = OnceLock::new();
    MILAN_CERT_CHAIN.get_or_init(|| {
        let certs = X509::stack_from_pem(include_bytes!("milan_ask_ark.pem"))?;
        if certs.len() != 2 {
            bail!("Malformed Milan ASK/ARK");
        }

        // ask, ark
        let vendor_certs = VendorCertificates {
            ask: certs[0].clone(),
            ark: certs[1].clone(),
        };
        Ok(vendor_certs)
    })
}

impl Snp {
    pub fn new() -> Result<Self> {
        let Result::Ok(vendor_certs) = load_milan_cert_chain() else {
            bail!("Failed to load Milan cert chain");
        };
        let vendor_certs = vendor_certs.clone();
        Ok(Self { vendor_certs })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VendorCertificates {
    ask: X509,
    ark: X509,
}

#[async_trait]
impl Verifier for Snp {
    async fn evaluate(
        &self,
        evidence: &[u8],
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<TeeEvidenceParsedClaim> {
        let SnpEvidence {
            attestation_report: report,
            cert_chain,
        } = serde_json::from_slice(evidence).context("Deserialize Quote failed.")?;

        verify_report_signature(&report, &cert_chain, &self.vendor_certs)?;

        if report.version != 2 {
            return Err(anyhow!("Unexpected report version"));
        }

        if report.vmpl != 0 {
            return Err(anyhow!("VMPL Check Failed"));
        }

        let ReportData::Value(expected_report_data) = expected_report_data else {
            bail!("Report Data unset");
        };

        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "SNP");

        if expected_report_data != report.report_data {
            bail!("Report Data Mismatch");
        }

        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            debug!("Check the binding of HOST_DATA.");
            let expected_init_data_hash =
                regularize_data(expected_init_data_hash, 32, "HOST_DATA", "SNP");
            if expected_init_data_hash != report.host_data {
                bail!("Host Data Mismatch");
            }
        }

        let claims_map = parse_tee_evidence(&report);
        let json = json!(claims_map);
        Ok(json)
    }
}

fn get_oid_octets<const N: usize>(
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

fn get_oid_int(vcek: &x509_parser::certificate::TbsCertificate, oid: Oid) -> Result<u8> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    let (_, val_int) = Integer::from_der(val)?;
    val_int.as_u8().context("Unexpected data size")
}

pub(crate) fn verify_report_signature(
    report: &AttestationReport,
    cert_chain: &[CertTableEntry],
    vendor_certs: &VendorCertificates,
) -> Result<()> {
    // check cert chain
    let VendorCertificates { ask, ark } = vendor_certs;
    let vcek = verify_cert_chain(cert_chain, ask, ark)?;

    // OpenSSL bindings do not expose custom extensions
    // Parse the vcek using x509_parser
    let vcek_der = &vcek.to_der()?;
    let parsed_vcek = X509Certificate::from_der(vcek_der)?.1.tbs_certificate;

    // verify vcek fields
    // chip id
    if get_oid_octets::<64>(&parsed_vcek, HW_ID_OID)? != report.chip_id {
        return Err(anyhow!("Chip ID mismatch"));
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_vcek, UCODE_SPL_OID)? != report.reported_tcb.microcode {
        return Err(anyhow!("Microcode version mismatch"));
    }

    if get_oid_int(&parsed_vcek, SNP_SPL_OID)? != report.reported_tcb.snp {
        return Err(anyhow!("SNP version mismatch"));
    }

    if get_oid_int(&parsed_vcek, TEE_SPL_OID)? != report.reported_tcb.tee {
        return Err(anyhow!("TEE version mismatch"));
    }

    if get_oid_int(&parsed_vcek, LOADER_SPL_OID)? != report.reported_tcb.bootloader {
        return Err(anyhow!("Boot loader version mismatch"));
    }

    // verify report signature
    let sig = ecdsa::EcdsaSig::try_from(&report.signature)?;
    let data = &bincode::serialize(&report)?[..=0x29f];

    let pub_key = EcKey::try_from(vcek.public_key()?)?;
    let signed = sig.verify(&sha384(data), &pub_key)?;
    if !signed {
        return Err(anyhow!("Signature validation failed."));
    }

    Ok(())
}

fn verify_signature(cert: &X509, issuer: &X509, name: &str) -> Result<()> {
    cert.verify(&(issuer.public_key()? as PKey<Public>))?
        .then_some(())
        .ok_or_else(|| anyhow!("Invalid {name} signature"))
}

fn verify_cert_chain(cert_chain: &[CertTableEntry], ask: &X509, ark: &X509) -> Result<X509> {
    let raw_vcek = cert_chain
        .iter()
        .find(|c| c.cert_type == CertType::VCEK)
        .ok_or_else(|| anyhow!("VCEK not found."))?;
    let vcek = x509::X509::from_der(raw_vcek.data()).context("Failed to load VCEK")?;

    // ARK -> ARK
    verify_signature(ark, ark, "ARK")?;
    // ARK -> ASK
    verify_signature(ask, ark, "ASK")?;
    // ASK -> VCEK
    verify_signature(&vcek, ask, "VCEK")?;

    Ok(vcek)
}

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

        // measurement
        "measurement": format!("{}", base64::engine::general_purpose::STANDARD.encode(report.measurement)),
    });

    claims_map as TeeEvidenceParsedClaim
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::nid::Nid;

    #[test]
    fn check_milan_certificates() {
        let VendorCertificates { ask, ark } = load_milan_cert_chain().as_ref().unwrap();
        assert_eq!(get_common_name(ark).unwrap(), "ARK-Milan");
        assert_eq!(get_common_name(ask).unwrap(), "SEV-Milan");

        assert!(ark
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ARK Signature")
            .unwrap());

        assert!(ask
            .verify(&(ark.public_key().unwrap() as PKey<Public>))
            .context("Invalid ASK Signature")
            .unwrap());
    }

    fn get_common_name(cert: &x509::X509) -> Result<String> {
        let mut entries = cert.subject_name().entries_by_nid(Nid::COMMONNAME);

        if let Some(e) = entries.next() {
            assert_eq!(entries.count(), 0);
            return Ok(e.data().as_utf8()?.to_string());
        }
        Err(anyhow!("No CN found"))
    }

    #[test]
    fn check_vcek_parsing() {
        let vcek_der = include_bytes!("test-vcek.der");
        let parsed_vcek = X509Certificate::from_der(vcek_der)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_parsing_legacy() {
        let vcek_der = include_bytes!("test-vcek-invalid-legacy.der");
        let parsed_vcek = X509Certificate::from_der(vcek_der)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_parsing_new() {
        let vcek_der = include_bytes!("test-vcek-invalid-new.der");
        let parsed_vcek = X509Certificate::from_der(vcek_der)
            .unwrap()
            .1
            .tbs_certificate;

        get_oid_octets::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_signature_verification() {
        let vcek = include_bytes!("test-vcek.der").to_vec();
        let cert_table = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        let VendorCertificates { ask, ark } = load_milan_cert_chain().as_ref().unwrap();
        verify_cert_chain(&cert_table, ask, ark).unwrap();
    }

    #[test]
    fn check_vcek_signature_failure() {
        let mut vcek = include_bytes!("test-vcek.der").to_vec();

        // corrupt some byte, while it should remain a valid cert
        vcek[42] += 1;
        X509::from_der(&vcek).expect("failed to parse der");

        let cert_table = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        let VendorCertificates { ask, ark } = load_milan_cert_chain().as_ref().unwrap();
        verify_cert_chain(&cert_table, ask, ark).unwrap_err();
    }

    #[test]
    fn check_milan_chain_signature_failure() {
        let vcek = include_bytes!("test-vcek.der").to_vec();
        let cert_table = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        let VendorCertificates { ask, ark } = load_milan_cert_chain().as_ref().unwrap();
        // toggle ark <=> ask
        verify_cert_chain(&cert_table, ark, ask).unwrap_err();
    }

    #[test]
    fn check_report_signature() {
        let vcek = include_bytes!("test-vcek.der").to_vec();
        let bytes = include_bytes!("test-report.bin");
        let attestation_report = bincode::deserialize::<AttestationReport>(bytes).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_report_signature(&attestation_report, &cert_chain, vendor_certs).unwrap();
    }

    #[test]
    fn check_report_signature_failure() {
        let vcek = include_bytes!("test-vcek.der").to_vec();
        let mut bytes = include_bytes!("test-report.bin").to_vec();

        // corrupt some byte
        bytes[42] += 1;

        let attestation_report = bincode::deserialize::<AttestationReport>(&bytes).unwrap();
        let cert_chain = vec![CertTableEntry::new(CertType::VCEK, vcek)];
        let vendor_certs = load_milan_cert_chain().as_ref().unwrap();
        verify_report_signature(&attestation_report, &cert_chain, vendor_certs).unwrap_err();
    }
}
