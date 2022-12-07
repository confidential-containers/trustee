use anyhow::{anyhow, Context, Result};
extern crate serde;
use self::serde::{Deserialize, Serialize};
use super::*;
use asn1_rs::{oid, Integer, Oid};
use async_trait::async_trait;
use kbs_types::TeePubKey;
use openssl::{
    ec::EcKey,
    ecdsa,
    pkey::{PKey, Public},
    x509,
};
use serde_json::json;
use sev::firmware::guest::types::AttestationReport;
use sev::firmware::host::types::{CertTableEntry, SnpCertType};
use sha2::{Digest, Sha384};
use x509_parser::prelude::*;

#[derive(Serialize, Deserialize)]
struct SnpEvidence {
    attestation_report: AttestationReport,
    cert_chain: Vec<CertTableEntry>,
}

const HW_ID_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .4);
const UCODE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .8);
const SNP_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .3);
const TEE_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .2);
const LOADER_SPL_OID: Oid<'static> = oid!(1.3.6 .1 .4 .1 .3704 .1 .3 .1);

#[derive(Debug, Default)]
pub struct Snp {}

#[async_trait]
impl Verifier for Snp {
    async fn evaluate(
        &self,
        nonce: String,
        attestation: &Attestation,
    ) -> Result<TeeEvidenceParsedClaim> {
        let tee_evidence = serde_json::from_str::<SnpEvidence>(&attestation.tee_evidence)
            .context("Deserialize Quote failed.")?;

        verify_report_signature(&tee_evidence)?;

        let report = tee_evidence.attestation_report;
        if report.version != 2 {
            return Err(anyhow!("Unexpected report version"));
        }

        if report.vmpl != 0 {
            return Err(anyhow!("VMPL Check Failed"));
        }

        let expected_report_data = calculate_expected_report_data(&nonce, &attestation.tee_pubkey);
        if report.report_data != expected_report_data {
            return Err(anyhow!("Report Data Mismatch"));
        }

        Ok(parse_tee_evidence(&report))
    }
}

fn get_oid<const N: usize>(
    vcek: &x509_parser::certificate::TbsCertificate,
    oid: Oid,
) -> Result<[u8; N]> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    val.try_into().context("Oid data has wrong length.")
}

fn get_oid_int(vcek: &x509_parser::certificate::TbsCertificate, oid: Oid) -> Result<u8> {
    let val = vcek
        .get_extension_unique(&oid)?
        .ok_or_else(|| anyhow!("Oid not found"))?
        .value;

    let (_, val_int) = Integer::from_der(val)?;
    val_int.as_u8().context("Unexpected data size")
}

fn verify_report_signature(evidence: &SnpEvidence) -> Result<()> {
    // check cert chain
    let vcek = verify_cert_chain(&evidence.cert_chain)?;

    // OpenSSL bindings do not expose custom extensions
    // Parse the vcek using x509_parser
    let vcek_der = &vcek.to_der()?;
    let parsed_vcek = X509Certificate::from_der(vcek_der)?.1.tbs_certificate;

    // verify vcek fields
    // chip id
    if get_oid::<64>(&parsed_vcek, HW_ID_OID)? != evidence.attestation_report.chip_id {
        return Err(anyhow!("Chip ID mismatch"));
    }

    // tcb version
    // these integer extensions are 3 bytes with the last byte as the data
    if get_oid_int(&parsed_vcek, UCODE_SPL_OID)?
        != evidence.attestation_report.reported_tcb.microcode
    {
        return Err(anyhow!("Microcode verion mismatch"));
    }

    if get_oid_int(&parsed_vcek, SNP_SPL_OID)? != evidence.attestation_report.reported_tcb.snp {
        return Err(anyhow!("SNP verion mismatch"));
    }

    if get_oid_int(&parsed_vcek, TEE_SPL_OID)? != evidence.attestation_report.reported_tcb.tee {
        return Err(anyhow!("TEE verion mismatch"));
    }

    if get_oid_int(&parsed_vcek, LOADER_SPL_OID)?
        != evidence.attestation_report.reported_tcb.boot_loader
    {
        return Err(anyhow!("Boot loader verion mismatch"));
    }

    // verify report signature
    let sig = ecdsa::EcdsaSig::try_from(&evidence.attestation_report.signature)?;
    let data = &bincode::serialize(&evidence.attestation_report)?[..=0x29f];

    sig.verify(data, EcKey::try_from(vcek.public_key()?)?.as_ref())
        .context("Signature validation failed.")?;

    Ok(())
}

fn load_milan_cert_chain() -> Result<(x509::X509, x509::X509)> {
    let certs = x509::X509::stack_from_pem(include_bytes!("milan_ask_ark.pem"))?;
    if certs.len() != 2 {
        bail!("Malformed Milan ASK/ARK");
    }

    // ask, ark
    Ok((certs[0].clone(), certs[1].clone()))
}

fn verify_cert_chain(cert_chain: &[CertTableEntry]) -> Result<x509::X509> {
    let (ask, ark) = load_milan_cert_chain()?;

    let raw_vcek = cert_chain
        .iter()
        .find(|c| c.cert_type == SnpCertType::VCEK)
        .ok_or_else(|| anyhow!("VCEK not found."))?;
    let vcek = x509::X509::from_der(raw_vcek.data()).context("Failed to load VCEK")?;

    // ARK -> ARK
    ark.verify(&(ark.public_key().unwrap() as PKey<Public>))
        .context("Invalid ARK Signature")?;

    // ARK -> ASK
    ask.verify(&(ark.public_key()? as PKey<Public>))
        .context("Invalid ASK Signature")?;

    // ASK -> VCEK
    vcek.verify(&(ask.public_key()? as PKey<Public>))
        .context("Invalid VCEK Signature")?;

    Ok(vcek)
}

fn calculate_expected_report_data(nonce: &String, tee_pubkey: &TeePubKey) -> [u8; 64] {
    let mut hasher = Sha384::new();

    hasher.update(nonce.as_bytes());
    hasher.update(&tee_pubkey.k_mod);
    hasher.update(&tee_pubkey.k_exp);

    let partial_hash = hasher.finalize();

    let mut hash = [0u8; 64];
    hash[..48].copy_from_slice(&partial_hash);

    hash
}

fn parse_tee_evidence(report: &AttestationReport) -> TeeEvidenceParsedClaim {
    let claims_map = json!({
        // policy fields
        "policy_abi_major": format!("{}",report.policy.abi_major()),
        "policy_abi_minor": format!("{}", report.policy.abi_minor()),
        "policy_smt_allowed": format!("{}", report.policy.smt_allowed()),
        "policy_migrate_ma": format!("{}", report.policy.migrate_ma_allowed()),
        "policy_debug_allowed": format!("{}", report.policy.debug_allowed()),
        "policy_single_socket": format!("{}", report.policy.single_socket_required()),

        // versioning info
        "reported_tcb_bootloader": format!("{}", report.reported_tcb.boot_loader),
        "reported_tcb_tee": format!("{}", report.reported_tcb.tee),
        "reported_tcb_snp": format!("{}", report.reported_tcb.snp),
        "reported_tcb_microcode": format!("{}", report.reported_tcb.microcode),

        // platform info
        "platform_tsme_enabled": format!("{}", report.plat_info.tsme_enabled()),
        "platform_smt_enabled": format!("{}", report.plat_info.smt_enabled()),

        // measurement
        "measurement": format!("{}", base64::encode(report.measurement)),
    });

    claims_map as TeeEvidenceParsedClaim
}

#[cfg(test)]
mod tests {
    use super::*;
    use openssl::nid::Nid;
    use sev::firmware::host::types::CertTableEntry;

    #[test]
    fn check_milan_certificates() {
        let (ask, ark) = load_milan_cert_chain().unwrap();
        assert_eq!(get_common_name(&ark).unwrap(), "ARK-Milan");
        assert_eq!(get_common_name(&ask).unwrap(), "SEV-Milan");

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

        get_oid::<64>(&parsed_vcek, HW_ID_OID).unwrap();
        let oids = vec![UCODE_SPL_OID, SNP_SPL_OID, TEE_SPL_OID, LOADER_SPL_OID];
        for oid in oids {
            get_oid_int(&parsed_vcek, oid).unwrap();
        }
    }

    #[test]
    fn check_vcek_signature_verification() {
        let vcek = include_bytes!("test-vcek.der").to_vec();
        let cert_table = vec![CertTableEntry::new(SnpCertType::VCEK, vcek)];
        verify_cert_chain(&cert_table).unwrap();
    }

    #[test]
    fn check_vcek_signature_failure() {
        let mut vcek = include_bytes!("test-vcek.der").to_vec();

        // corrupt some byte
        vcek[7] += 1;

        let cert_table = vec![CertTableEntry::new(SnpCertType::VCEK, vcek)];
        assert!(verify_cert_chain(&cert_table).is_err());
    }
}
