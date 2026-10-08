use eventlog::CcEventLog;

use anyhow::anyhow;
use tracing::{debug, error, info, instrument, warn};

use crate::tdx::claims::generate_parsed_claim;

use super::*;
use crate::intel_dcap::{
    collateral::build_quote_collateral,
    collateral_service::CollateralService,
    ecdsa_quote_verification, extend_using_custom_claims,
    pck::parse_platform_info,
    quote::{parse_quote, Quote},
    QcnlConfig,
};
use async_trait::async_trait;
use base64::Engine;
use serde::{Deserialize, Serialize};

pub(crate) mod claims;

#[derive(Serialize, Deserialize, Debug)]
struct TdxEvidence {
    // Base64 encoded CC Eventlog ACPI table
    // refer to https://uefi.org/specs/ACPI/6.5/05_ACPI_Software_Programming_Model.html#cc-event-log-acpi-table.
    cc_eventlog: Option<String>,
    // Base64 encoded TD quote.
    quote: String,
}

#[derive(Debug, Default)]
pub struct Tdx {
    config: QcnlConfig,
}

impl Tdx {
    pub(crate) fn new(config: Option<QcnlConfig>) -> Self {
        Self {
            config: config.unwrap_or_default(),
        }
    }
}

#[async_trait]
impl Verifier for Tdx {
    #[instrument(skip_all, name = "Intel TDX")]
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<Vec<(TeeEvidenceParsedClaim, TeeClass)>> {
        let tdx_evidence = serde_json::from_value::<TdxEvidence>(evidence)
            .context("Deserialize TDX Evidence failed.")?;

        let pcs = self.config.pcs()?;
        let claims = verify_evidence(
            expected_report_data,
            expected_init_data_hash,
            tdx_evidence,
            &pcs,
        )
        .await
        .context("TDX Verifier")?;

        Ok(vec![(claims, "cpu".to_string())])
    }
}

async fn verify_evidence(
    expected_report_data: &ReportData<'_>,
    expected_init_data_hash: &InitDataHash<'_>,
    evidence: TdxEvidence,
    cs: &impl CollateralService,
) -> Result<TeeEvidenceParsedClaim> {
    if evidence.quote.is_empty() {
        bail!("TDX Quote is empty.");
    }

    // Verify TD quote ECDSA signature.
    let quote_bin = base64::engine::general_purpose::STANDARD.decode(evidence.quote)?;

    // Parse quote early so PlatformInfo is available for collateral fetch.
    let quote = parse_quote(&quote_bin)?;
    if matches!(quote, Quote::V3 { .. }) {
        bail!("expected TDX quote (v4/v5), got SGX quote (v3)");
    }

    debug!("{quote}");

    let platform_info = parse_platform_info(quote.cert_data().qe_certification_data.certificates)?;

    let collateral = build_quote_collateral(
        platform_info.fmspc,
        platform_info.is_platform_ca,
        quote.tee_type(),
        cs,
    )
    .await?;

    let custom_claims = ecdsa_quote_verification(quote_bin.as_slice(), Some(collateral))?;

    info!("Quote DCAP check succeeded.");

    if let ReportData::Value(expected_report_data) = expected_report_data {
        debug!("Check the binding of REPORT_DATA.");
        let expected_report_data = regularize_data(expected_report_data, 64, "REPORT_DATA", "TDX");
        if expected_report_data != quote.report_data() {
            bail!("REPORT_DATA is different from that in TDX Quote");
        }
    }

    let ccel = match &evidence.cc_eventlog {
        Some(el) if !el.is_empty() => {
            let ccel_data = base64::engine::general_purpose::STANDARD.decode(el)?;
            let ccel = CcEventLog::try_from(ccel_data)
                .map_err(|e| anyhow!("Parse CC Eventlog failed: {:?}", e))?;
            Some(ccel)
        }
        _ => {
            warn!("No Eventlog included inside the TDX evidence.");
            None
        }
    };

    let rtmrs = [
        quote.rtmr_0(),
        quote.rtmr_1(),
        quote.rtmr_2(),
        quote.rtmr_3(),
    ];
    let ccel = ccel
        .map(|ccel| VerifiedCcEventLog::verify(ccel, rtmrs))
        .transpose()?;

    verify_init_data(quote.mr_config_id(), ccel.as_ref(), expected_init_data_hash)?;

    // Return Evidence parsed claim
    let ccel = ccel.map(VerifiedCcEventLog::into_inner);
    let mut claim = generate_parsed_claim(&quote, ccel, &platform_info)?;
    extend_using_custom_claims(&mut claim, custom_claims)?;

    Ok(claim)
}

/// Index of RTMR3 in the CC eventlog, where AA records runtime events.
const RTMR3_INDEX: u32 = 4;

const COCO_EVENT_DOMAIN: &str = "github.com/confidential-containers";

mod verified_ccel {
    use anyhow::Result;
    use eventlog::{ccel::tcg_enum::TcgAlgorithm, CcEventLog, EventlogEntry, ReferenceMeasurement};
    use tracing::info;

    /// A CC eventlog whose replay matched the RTMRs in the quote. `verify` is the only way to
    /// build one, so code holding it can trust the entries' digests.
    pub(super) struct VerifiedCcEventLog(CcEventLog);

    impl VerifiedCcEventLog {
        pub(super) fn verify(ccel: CcEventLog, rtmrs: [&[u8]; 4]) -> Result<Self> {
            let compare_obj = rtmrs
                .iter()
                .zip(1..)
                .map(|(rtmr, index)| ReferenceMeasurement {
                    index,
                    algorithm: TcgAlgorithm::Sha384,
                    reference: rtmr.to_vec(),
                    initial_value: vec![],
                })
                .collect();
            ccel.replay_and_match(compare_obj)?;
            info!("EventLog integrity check succeeded.");
            Ok(Self(ccel))
        }

        pub(super) fn entries(&self) -> &[EventlogEntry] {
            &self.0.log
        }

        pub(super) fn into_inner(self) -> CcEventLog {
            self.0
        }
    }
}

use verified_ccel::VerifiedCcEventLog;

/// Check that the initdata is bound to the TD.
///
/// A non-zero MRCONFIGID must match the initdata digest. An all-zero MRCONFIGID means the host
/// could not set it (e.g. on some CSPs), so the initdata must be bound by exactly one `InitData`
/// event in RTMR3 instead.
fn verify_init_data(
    mr_config_id: &[u8],
    ccel: Option<&VerifiedCcEventLog>,
    expected_init_data_hash: &InitDataHash,
) -> Result<()> {
    let InitDataHash::Value(expected) = expected_init_data_hash else {
        return Ok(());
    };

    if mr_config_id.iter().any(|b| *b != 0) {
        debug!("Check the binding of MRCONFIGID.");
        let expected = regularize_data(expected, 48, "MRCONFIGID", "TDX");
        if expected != mr_config_id {
            error!(
                "MRCONFIGID (Initdata) verification failed: expected {}, got {}",
                hex::encode(&expected),
                hex::encode(mr_config_id)
            );
            bail!("MRCONFIGID is different from that in TDX Quote");
        }
        info!("MRCONFIGID check succeeded.");
        return Ok(());
    }

    debug!("MRCONFIGID is not set, check the InitData event in RTMR3.");
    let ccel = ccel.context("MRCONFIGID is not set and no eventlog binds the initdata")?;
    check_init_data_event(ccel, RTMR3_INDEX, expected)?;
    info!("InitData event check succeeded.");
    Ok(())
}

/// Require exactly one CoCo `InitData` event in the given register, whose digest matches
/// `expected`.
fn check_init_data_event(ccel: &VerifiedCcEventLog, index: u32, expected: &[u8]) -> Result<()> {
    let matching: Vec<_> = ccel
        .entries()
        .iter()
        .filter_map(|entry| {
            if entry.index != index {
                return None;
            }
            let data = entry.details.data.as_ref()?;
            (data["domain"] == COCO_EVENT_DOMAIN && data["operation"] == "InitData")
                .then_some((entry, data))
        })
        .collect();
    let [(entry, event)] = matching.as_slice() else {
        bail!(
            "expected exactly one InitData event in the eventlog, found {}",
            matching.len()
        );
    };
    // The replay only covers the entry's digest, so the text read below must hash to it.
    if !entry.digest_matches_event {
        bail!("InitData event data does not match its digest");
    }

    let digest = event["content"]["digest"]
        .as_str()
        .context("InitData event has no digest")?;
    let (alg, value) = digest
        .split_once(':')
        .context("InitData digest has no algorithm")?;
    let alg_fits = match expected.len() {
        32 => matches!(alg, "sha256" | "sm3"),
        48 => alg == "sha384",
        64 => alg == "sha512",
        _ => false,
    };
    if !alg_fits || value != hex::encode(expected) {
        bail!("InitData event digest {digest} does not match the initdata");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::intel_dcap::quote::parse_quote;
    use crate::tdx::claims::generate_parsed_claim;
    use eventlog::CcEventLog;
    use std::fs;

    #[test]
    fn test_generate_parsed_claim() {
        use crate::intel_dcap::pck::parse_platform_info;

        let ccel_bin = fs::read("./test_data/CCEL_data").unwrap();
        let ccel = CcEventLog::try_from(ccel_bin).unwrap();
        let quote_bin = fs::read("./test_data/tdx_quote_4.dat").unwrap();
        let quote = parse_quote(&quote_bin).unwrap();
        let platform_info =
            parse_platform_info(quote.cert_data().qe_certification_data.certificates).unwrap();

        let parsed_claim = generate_parsed_claim(&quote, Some(ccel), &platform_info);
        assert!(parsed_claim.is_ok());

        let _ = fs::write(
            "./test_data/evidence_claim_output.txt",
            format!("{:?}", parsed_claim.unwrap()),
        );
    }

    mod init_data {
        use super::super::*;
        use sha2::{Digest, Sha384};

        const INITDATA: [u8; 48] = [7; 48];
        const ZERO: [u8; 48] = [0; 48];

        /// An AAEL entry as AA appends it after the CCEL.
        fn aael_entry(index: u32, text: &str) -> Vec<u8> {
            let mut data = 0x4141454c_u32.to_le_bytes().to_vec();
            data.extend((text.len() as u32).to_le_bytes());
            data.extend(text.as_bytes());

            let mut entry = index.to_le_bytes().to_vec();
            entry.extend(0x6_u32.to_le_bytes()); // EV_EVENT_TAG
            entry.extend(1_u32.to_le_bytes()); // one digest
            entry.extend(0xC_u16.to_le_bytes()); // SHA-384
            entry.extend(Sha384::digest(&data));
            entry.extend((data.len() as u32).to_le_bytes());
            entry.extend(data);
            entry
        }

        fn init_data_event(digest: &[u8]) -> String {
            format!(
                r#"{COCO_EVENT_DOMAIN} InitData {{"digest":"sha384:{}"}}"#,
                hex::encode(digest)
            )
        }

        /// The spec ID header of a real GCP CCEL followed by `texts` as RTMR3 events, and
        /// the RTMR3 value those events replay to.
        fn eventlog(texts: &[String]) -> (CcEventLog, Vec<u8>) {
            let ccel = std::fs::read("../eventlog/test_data/CCEL_data_gcp").unwrap();
            let header_len = 32 + u32::from_le_bytes(ccel[28..32].try_into().unwrap()) as usize;
            let mut log = ccel[..header_len].to_vec();
            let mut rtmr3 = ZERO.to_vec();
            for text in texts {
                let entry = aael_entry(RTMR3_INDEX, text);
                let digest = &entry[14..62];
                rtmr3 = Sha384::digest([&rtmr3[..], digest].concat()).to_vec();
                log.extend(entry);
            }
            (CcEventLog::try_from(log).unwrap(), rtmr3)
        }

        fn verify(mr_config_id: &[u8], ccel: Option<&CcEventLog>, rtmr3: &[u8]) -> Result<()> {
            let ccel = ccel
                .cloned()
                .map(|ccel| VerifiedCcEventLog::verify(ccel, [&ZERO, &ZERO, &ZERO, rtmr3]))
                .transpose()?;
            verify_init_data(mr_config_id, ccel.as_ref(), &InitDataHash::Value(&INITDATA))
        }

        #[test]
        fn accepts_one_matching_event_when_mrconfigid_is_unset() {
            let pull = r#"github.com/confidential-containers PullImage {"image":"busybox"}"#;
            let (ccel, rtmr3) = eventlog(&[init_data_event(&INITDATA), pull.into()]);
            verify(&ZERO, Some(&ccel), &rtmr3).unwrap();
        }

        #[test]
        fn rejects_an_event_with_another_digest() {
            let (ccel, rtmr3) = eventlog(&[init_data_event(&[8; 48])]);
            assert!(verify(&ZERO, Some(&ccel), &rtmr3).is_err());
        }

        #[test]
        fn rejects_two_events() {
            let event = init_data_event(&INITDATA);
            let (ccel, rtmr3) = eventlog(&[event.clone(), event]);
            assert!(verify(&ZERO, Some(&ccel), &rtmr3).is_err());
        }

        #[test]
        fn rejects_no_event_or_no_eventlog() {
            let (ccel, rtmr3) = eventlog(&[]);
            assert!(verify(&ZERO, Some(&ccel), &rtmr3).is_err());
            assert!(verify(&ZERO, None, &ZERO).is_err());
        }

        #[test]
        fn rejects_an_unlogged_extend() {
            let (ccel, rtmr3) = eventlog(&[init_data_event(&INITDATA)]);
            let extended = Sha384::digest([&rtmr3[..], &[1; 48]].concat());
            assert!(verify(&ZERO, Some(&ccel), &extended).is_err());
        }

        #[test]
        fn rejects_an_event_whose_text_was_edited() {
            // Keep the digest of the logged event but swap in the text of another one, so the
            // replay still matches.
            let genuine = aael_entry(RTMR3_INDEX, &init_data_event(&[8; 48]));
            let forged = aael_entry(RTMR3_INDEX, &init_data_event(&INITDATA));
            let mut edited = forged.clone();
            edited[14..62].copy_from_slice(&genuine[14..62]);

            let ccel = std::fs::read("../eventlog/test_data/CCEL_data_gcp").unwrap();
            let header_len = 32 + u32::from_le_bytes(ccel[28..32].try_into().unwrap()) as usize;
            let mut log = ccel[..header_len].to_vec();
            log.extend(edited);
            let ccel = CcEventLog::try_from(log).unwrap();
            let rtmr3 = Sha384::digest([&ZERO[..], &genuine[14..62]].concat());

            assert!(verify(&ZERO, Some(&ccel), &rtmr3).is_err());
        }

        #[test]
        fn a_set_mrconfigid_never_falls_back_to_the_event() {
            let (ccel, rtmr3) = eventlog(&[init_data_event(&INITDATA)]);
            assert!(verify(&[9; 48], Some(&ccel), &rtmr3).is_err());
            verify(&INITDATA, Some(&ccel), &rtmr3).unwrap();
        }
    }
}
