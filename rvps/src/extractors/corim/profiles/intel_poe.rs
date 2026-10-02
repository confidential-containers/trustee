// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Intel Platform Ownership Endorsement (POE) profile
//! (`tag:intel.com,2026:tee.poe#1.0`, produced by `poe-gen-tool`), as
//! specified by draft-bzb-rats-intel-poe-endorsements.
//!
//! POE CoRIMs bind a Platform Instance ID (PIID) to an owner name via a
//! conditional-endorsement triple: "if the platform's PIID is X, its owner
//! is Y". Both mval fields are POE profile-private extension keys, so they
//! land in `MeasurementValuesMap::extensions` rather than any of corim_rs's
//! named mval fields.
//!
//! ## Conformance
//!
//! The extractor follows the draft's rules for verifiers: unknown fields
//! are ignored, and a CoRIM that violates the profile is rejected with an
//! error rather than yielding no reference values. It also requires one
//! measurement-map per clause, as the profile's CDDL does. The draft's
//! rules on the COSE signature and its signing chain apply to the signed
//! POE and aren't checked here.

use anyhow::{Context, Result, bail, ensure};
use chrono::{DateTime, Utc};
use corim_rs::{
    ClassIdTypeChoice, ConciseMidTag, CorimMap, EnvironmentMap, ExtensionValue, Integer,
    IntegerTime, MeasurementMap, ProfileTypeChoice,
};

use crate::ReferenceValue;

use super::super::tag_as_comid;
use super::CorimProfileExtractor;

/// The profile identifier up to and including the `#` that starts its
/// `<major>.<minor>` version fragment.
const PROFILE_ID_PREFIX: &str = "tag:intel.com,2026:tee.poe#";
const SUPPORTED_MAJOR_VERSION: u64 = 1;
const PIID_ENV_OID: &str = "2.16.840.1.113741.1.13.2.6.1";
const OWNER_ENDORSE_OID: &str = "2.16.840.1.113741.1.13.2.12.1";
/// mval key `tee.platform-instance-id`, carrying the PIID.
const TEE_PLATFORM_INSTANCE_ID: i128 = -101;
/// mval key `tee.owner-name`, carrying the owner name.
const TEE_OWNER_NAME: i128 = -401;
const PIID_LENGTHS: [usize; 2] = [16, 32];
const OWNER_NAME_MAX_LEN: usize = 1024;
/// RVs are named after the profile's tag URI, `tag:intel.com,2026:tee.poe`.
const RV_NAME_PREFIX: &str = "intel.com/tee.poe/";

pub(super) struct IntelPoeExtractor;

impl CorimProfileExtractor for IntelPoeExtractor {
    /// Claims every CoRIM that declares the POE profile family, including
    /// unsupported versions and encodings, so that those are rejected rather
    /// than handed to generic extraction.
    fn handles(&self, profile: &ProfileTypeChoice) -> bool {
        match profile {
            ProfileTypeChoice::Uri(uri) => uri.to_string().starts_with(PROFILE_ID_PREFIX),
            ProfileTypeChoice::Extension(ExtensionValue::Text(text)) => {
                text.to_string().starts_with(PROFILE_ID_PREFIX)
            }
            _ => false,
        }
    }

    /// The resulting RV is named `intel.com/tee.poe/<piid-hex>` so a policy
    /// can look up the expected owner for a platform by the PIID reported
    /// in that platform's own evidence.
    fn extract(&self, corim: &CorimMap) -> Result<Vec<ReferenceValue>> {
        extract_at(corim, Utc::now())
    }
}

/// Extracts the POE binding, checking `rim-validity` against `now`.
fn extract_at(corim: &CorimMap, now: DateTime<Utc>) -> Result<Vec<ReferenceValue>> {
    check_profile(corim.profile.as_ref())?;
    let not_after = check_validity(corim, now)?;

    let [tag] = corim.tags.as_slice() else {
        bail!(
            "POE CoRIM must carry exactly one tag, found {}",
            corim.tags.len()
        );
    };
    let comid = tag_as_comid(tag).context("POE CoRIM tag is not a CoMID")?;
    let binding = PoeBinding::from_comid(&comid)?;

    let name = format!("{RV_NAME_PREFIX}{}", hex::encode(&binding.piid));
    let rv = ReferenceValue::new()?
        .set_name(&name)
        .set_value(serde_json::json!({ "owner-name": binding.owner_name }))
        .set_expiration(not_after);

    Ok(vec![rv])
}

/// Checks that the CoRIM's `rim-validity` carries both bounds and that
/// `now` falls within them, returning `not-after`.
fn check_validity(corim: &CorimMap, now: DateTime<Utc>) -> Result<DateTime<Utc>> {
    let validity = corim
        .rim_validity
        .as_ref()
        .context("POE CoRIM must carry rim-validity")?;
    let not_before = validity
        .not_before
        .as_ref()
        .context("POE rim-validity must carry not-before")?;
    let not_before = to_datetime(not_before).context("Invalid POE rim-validity not-before")?;
    let not_after =
        to_datetime(&validity.not_after).context("Invalid POE rim-validity not-after")?;

    ensure!(
        not_before <= not_after,
        "POE rim-validity not-before ({not_before}) is after not-after ({not_after})"
    );
    ensure!(now >= not_before, "POE is not valid before {not_before}");
    ensure!(now <= not_after, "POE expired at {not_after}");

    Ok(not_after)
}

fn to_datetime(time: &IntegerTime) -> Option<DateTime<Utc>> {
    DateTime::from_timestamp(i64::try_from(time.as_i128()).ok()?, 0)
}

/// Accepts the POE profile URI on the supported major version, with any
/// minor version, per the draft's versioning rules.
fn check_profile(profile: Option<&ProfileTypeChoice>) -> Result<()> {
    let Some(ProfileTypeChoice::Uri(uri)) = profile else {
        bail!("POE CoRIM profile must be encoded as a uri (CBOR tag 32)");
    };
    let uri = uri.to_string();
    let version = uri
        .strip_prefix(PROFILE_ID_PREFIX)
        .with_context(|| format!("Not a POE profile identifier: {uri}"))?;

    let parse_component = |component: &str| {
        if !component.is_empty() && component.bytes().all(|b| b.is_ascii_digit()) {
            component.parse::<u64>().ok()
        } else {
            None
        }
    };
    let (major, _minor) = version
        .split_once('.')
        .and_then(|(major, minor)| Some((parse_component(major)?, parse_component(minor)?)))
        .with_context(|| format!("Malformed POE profile version in {uri}"))?;

    ensure!(
        major == SUPPORTED_MAJOR_VERSION,
        "Unsupported POE profile major version in {uri}"
    );
    Ok(())
}

/// A validated (PIID, owner name) binding: only constructed by
/// `from_comid`, after every structural and value constraint the profile
/// places on it has been checked.
#[derive(Debug)]
struct PoeBinding {
    piid: Vec<u8>,
    owner_name: String,
}

impl PoeBinding {
    fn from_comid(comid: &ConciseMidTag) -> Result<Self> {
        let triples = comid
            .triples
            .conditional_endorsement_triples
            .as_deref()
            .unwrap_or_default();
        let [triple] = triples else {
            bail!(
                "POE CoMID must carry exactly one conditional-endorsement triple, found {}",
                triples.len()
            );
        };

        let [condition] = triple.conditions.as_slice() else {
            bail!(
                "POE triple must carry exactly one condition, found {}",
                triple.conditions.len()
            );
        };
        let [endorsement] = triple.endorsements.as_slice() else {
            bail!(
                "POE triple must carry exactly one endorsement, found {}",
                triple.endorsements.len()
            );
        };

        let claim =
            clause_measurement(&condition.environment, &condition.claims_list, PIID_ENV_OID)?;
        let piid = match mval_extension(claim, TEE_PLATFORM_INSTANCE_ID) {
            Some(ExtensionValue::Bytes(bytes)) => bytes.as_slice().to_vec(),
            Some(_) => bail!("POE PIID is not a byte string"),
            None => bail!("POE condition carries no PIID"),
        };
        ensure!(
            PIID_LENGTHS.contains(&piid.len()),
            "POE PIID must be 16 or 32 bytes, found {}",
            piid.len()
        );

        let claim = clause_measurement(
            &endorsement.condition,
            &endorsement.endorsement,
            OWNER_ENDORSE_OID,
        )?;
        let owner_name = match mval_extension(claim, TEE_OWNER_NAME) {
            Some(ExtensionValue::Text(text)) => text.to_string(),
            Some(_) => bail!("POE owner name is not a text string"),
            None => bail!("POE endorsement carries no owner name"),
        };
        ensure!(
            (1..=OWNER_NAME_MAX_LEN).contains(&owner_name.len()),
            "POE owner name must be 1 to {OWNER_NAME_MAX_LEN} bytes, found {}",
            owner_name.len()
        );

        Ok(Self { piid, owner_name })
    }
}

/// Returns the single measurement-map of a clause of the triple, after
/// checking that the clause's environment has class-id `class_oid`. An
/// `authorized-by` is rejected: the issuer's authority comes from the COSE
/// signing chain, not from a per-measurement key.
fn clause_measurement<'a, 'b>(
    env: &EnvironmentMap,
    measurements: &'a [MeasurementMap<'b>],
    class_oid: &str,
) -> Result<&'a MeasurementMap<'b>> {
    let class_id = env.class.as_ref().and_then(|class| class.class_id.as_ref());
    ensure!(
        matches!(class_id, Some(ClassIdTypeChoice::Oid(oid)) if oid.to_string() == class_oid),
        "POE environment class-id must be OID {class_oid}"
    );
    let [measurement] = measurements else {
        bail!(
            "POE clause of class {class_oid} must carry exactly one measurement-map, found {}",
            measurements.len()
        );
    };
    ensure!(
        measurement.authorized_by.is_none(),
        "POE clause of class {class_oid} must not carry authorized-by"
    );
    Ok(measurement)
}

fn mval_extension<'a>(
    measurement: &'a MeasurementMap,
    key: i128,
) -> Option<&'a ExtensionValue<'a>> {
    measurement.mval.extensions.as_ref()?.0.get(&Integer(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corim_rs::{Bytes, ConditionalEndorsementTripleRecord, Corim, ObjectIdentifier, Uri};
    use rstest::rstest;

    /// Same fixture as the parent module's end-to-end POE test.
    const POE_CORIM: &[u8] = include_bytes!("../poe-example-corim.cbor");
    const POE_PIID_HEX: &str = "021ac64d355ba904e2d5948d228d5482";
    /// The fixture's rim-validity window.
    const POE_NOT_BEFORE: i64 = 1790947551; // 2026-10-02T13:25:51Z
    const POE_NOT_AFTER: i64 = 1948627551; // 2031-10-01T13:25:51Z

    fn at(timestamp: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(timestamp, 0).unwrap()
    }

    /// Runs the POE extractor over the fixture, after letting the caller
    /// tweak its decoded CoRIM.
    fn extract_with(mutate: impl FnOnce(&mut CorimMap)) -> Result<Vec<ReferenceValue>> {
        extract_with_at(mutate, at(POE_NOT_BEFORE + 1))
    }

    fn extract_with_at(
        mutate: impl FnOnce(&mut CorimMap),
        now: DateTime<Utc>,
    ) -> Result<Vec<ReferenceValue>> {
        let corim = Corim::from_cbor(POE_CORIM).unwrap();
        let mut corim_map = corim.as_map_ref().clone();

        mutate(&mut corim_map);

        extract_at(&corim_map, now)
    }

    /// Parses the fixture's binding, after letting the caller tweak its CoMID.
    fn binding_with(mutate: impl FnOnce(&mut ConciseMidTag)) -> Result<PoeBinding> {
        let corim = Corim::from_cbor(POE_CORIM).unwrap();
        let mut comid = tag_as_comid(&corim.as_map_ref().tags[0])
            .unwrap()
            .into_owned();

        mutate(&mut comid);

        PoeBinding::from_comid(&comid)
    }

    fn triple<'a, 'b>(
        comid: &'a mut ConciseMidTag<'b>,
    ) -> &'a mut ConditionalEndorsementTripleRecord<'b> {
        &mut comid
            .triples
            .conditional_endorsement_triples
            .as_mut()
            .unwrap()[0]
    }

    fn condition_claim<'a, 'b>(comid: &'a mut ConciseMidTag<'b>) -> &'a mut MeasurementMap<'b> {
        &mut triple(comid).conditions[0].claims_list[0]
    }

    fn endorsement_claim<'a, 'b>(comid: &'a mut ConciseMidTag<'b>) -> &'a mut MeasurementMap<'b> {
        &mut triple(comid).endorsements[0].endorsement[0]
    }

    fn set_mval(measurement: &mut MeasurementMap, key: i128, value: ExtensionValue<'static>) {
        measurement
            .mval
            .extensions
            .as_mut()
            .unwrap()
            .0
            .insert(Integer(key), value);
    }

    fn remove_mval(measurement: &mut MeasurementMap, key: i128) {
        measurement
            .mval
            .extensions
            .as_mut()
            .unwrap()
            .0
            .remove(&Integer(key));
    }

    #[test]
    fn extracts_fixture_binding() {
        let rvs = extract_with(|_| ()).unwrap();
        assert_eq!(rvs.len(), 1);
        assert_eq!(rvs[0].name, format!("intel.com/tee.poe/{POE_PIID_HEX}"));
        assert_eq!(
            rvs[0].value,
            serde_json::json!({ "owner-name": "ACME-DC1" })
        );
        assert_eq!(rvs[0].expiration, at(POE_NOT_AFTER));
    }

    #[rstest]
    #[case::before_window(POE_NOT_BEFORE - 1, false)]
    #[case::at_not_before(POE_NOT_BEFORE, true)]
    #[case::at_not_after(POE_NOT_AFTER, true)]
    #[case::after_window(POE_NOT_AFTER + 1, false)]
    fn validity_window(#[case] now: i64, #[case] accepted: bool) {
        let result = extract_with_at(|_| (), at(now));
        assert_eq!(result.is_ok(), accepted);
    }

    #[rstest]
    #[case::missing_rim_validity(|corim: &mut CorimMap| corim.rim_validity = None)]
    #[case::missing_not_before(|corim: &mut CorimMap| {
        corim.rim_validity.as_mut().unwrap().not_before = None
    })]
    #[case::inverted_validity(|corim: &mut CorimMap| {
        corim.rim_validity.as_mut().unwrap().not_before = Some((POE_NOT_AFTER + 1).into())
    })]
    #[case::extra_tag(|corim: &mut CorimMap| {
        let tag = corim.tags[0].clone();
        corim.tags.push(tag);
    })]
    #[case::no_tags(|corim: &mut CorimMap| corim.tags.clear())]
    fn rejects_invalid_corim(#[case] mutate: fn(&mut CorimMap)) {
        assert!(extract_with(mutate).is_err());
    }

    #[rstest]
    #[case::current("1.0", true)]
    #[case::newer_minor("1.7", true)]
    #[case::multi_digit_minor("1.10", true)]
    #[case::newer_major("2.0", false)]
    #[case::older_major("0.9", false)]
    #[case::no_minor("1", false)]
    #[case::empty_minor("1.", false)]
    #[case::non_numeric_minor("1.x", false)]
    #[case::extra_component("1.0.1", false)]
    #[case::signed_minor("1.+1", false)]
    fn profile_versions(#[case] version: &str, #[case] accepted: bool) {
        let uri = format!("{PROFILE_ID_PREFIX}{version}");
        let profile = ProfileTypeChoice::Uri(Uri::from(uri.as_str()));

        assert!(IntelPoeExtractor.handles(&profile));
        assert_eq!(check_profile(Some(&profile)).is_ok(), accepted);
    }

    /// The profile must be a uri (CBOR tag 32). A profile given as a plain
    /// text string is still claimed as POE, so it's rejected instead of
    /// falling back to generic extraction.
    #[test]
    fn rejects_untagged_profile() {
        let profile = ProfileTypeChoice::Extension(ExtensionValue::Text(
            format!("{PROFILE_ID_PREFIX}1.0").into(),
        ));

        assert!(IntelPoeExtractor.handles(&profile));
        assert!(check_profile(Some(&profile)).is_err());
    }

    #[test]
    fn ignores_other_profiles() {
        let other = ProfileTypeChoice::Uri(Uri::from("tag:example.com,2026:other#1.0"));
        let oid = ProfileTypeChoice::Oid(
            ObjectIdentifier::try_from("2.16.840.1.113741.1")
                .unwrap()
                .into(),
        );

        assert!(!IntelPoeExtractor.handles(&other));
        assert!(!IntelPoeExtractor.handles(&oid));
    }

    #[test]
    fn rejects_missing_profile() {
        assert!(check_profile(None).is_err());
    }

    #[rstest]
    #[case::extra_triple(|comid: &mut ConciseMidTag| {
        let triples = comid.triples.conditional_endorsement_triples.as_mut().unwrap();
        triples.push(triples[0].clone());
    })]
    #[case::no_triple(|comid: &mut ConciseMidTag| {
        comid.triples.conditional_endorsement_triples = None
    })]
    #[case::extra_condition(|comid: &mut ConciseMidTag| {
        let conditions = &mut triple(comid).conditions;
        conditions.push(conditions[0].clone());
    })]
    #[case::extra_endorsement(|comid: &mut ConciseMidTag| {
        let endorsements = &mut triple(comid).endorsements;
        endorsements.push(endorsements[0].clone());
    })]
    #[case::extra_condition_measurement(|comid: &mut ConciseMidTag| {
        let claims = &mut triple(comid).conditions[0].claims_list;
        claims.push(claims[0].clone());
    })]
    #[case::extra_endorsement_measurement(|comid: &mut ConciseMidTag| {
        let measurements = &mut triple(comid).endorsements[0].endorsement;
        measurements.push(measurements[0].clone());
    })]
    #[case::authorized_by_on_condition(|comid: &mut ConciseMidTag| {
        condition_claim(comid).authorized_by = Some(vec![])
    })]
    #[case::authorized_by_on_endorsement(|comid: &mut ConciseMidTag| {
        endorsement_claim(comid).authorized_by = Some(vec![])
    })]
    #[case::wrong_condition_class(|comid: &mut ConciseMidTag| {
        let triple = triple(comid);
        triple.conditions[0].environment = triple.endorsements[0].condition.clone();
    })]
    #[case::wrong_endorsement_class(|comid: &mut ConciseMidTag| {
        let triple = triple(comid);
        triple.endorsements[0].condition = triple.conditions[0].environment.clone();
    })]
    #[case::non_bytes_piid(|comid: &mut ConciseMidTag| {
        set_mval(
            condition_claim(comid),
            TEE_PLATFORM_INSTANCE_ID,
            ExtensionValue::Text(POE_PIID_HEX.into()),
        )
    })]
    #[case::missing_piid(|comid: &mut ConciseMidTag| {
        remove_mval(condition_claim(comid), TEE_PLATFORM_INSTANCE_ID)
    })]
    #[case::non_text_owner_name(|comid: &mut ConciseMidTag| {
        set_mval(
            endorsement_claim(comid),
            TEE_OWNER_NAME,
            ExtensionValue::Bytes(Bytes::new(b"ACME-DC1".to_vec())),
        )
    })]
    #[case::missing_owner_name(|comid: &mut ConciseMidTag| {
        remove_mval(endorsement_claim(comid), TEE_OWNER_NAME)
    })]
    fn rejects_invalid_binding(#[case] mutate: fn(&mut ConciseMidTag)) {
        assert!(binding_with(mutate).is_err());
    }

    #[rstest]
    #[case::empty(0, false)]
    #[case::short(15, false)]
    #[case::sixteen(16, true)]
    #[case::between(24, false)]
    #[case::thirty_two(32, true)]
    #[case::long(33, false)]
    fn piid_lengths(#[case] len: usize, #[case] accepted: bool) {
        let result = binding_with(|comid| {
            set_mval(
                condition_claim(comid),
                TEE_PLATFORM_INSTANCE_ID,
                ExtensionValue::Bytes(Bytes::new(vec![0xab; len])),
            )
        });
        assert_eq!(result.is_ok(), accepted);
        if let Ok(binding) = result {
            assert_eq!(binding.piid, vec![0xab; len]);
        }
    }

    #[rstest]
    #[case::empty(0, false)]
    #[case::single(1, true)]
    #[case::max(OWNER_NAME_MAX_LEN, true)]
    #[case::too_long(OWNER_NAME_MAX_LEN + 1, false)]
    fn owner_name_lengths(#[case] len: usize, #[case] accepted: bool) {
        let result = binding_with(|comid| {
            set_mval(
                endorsement_claim(comid),
                TEE_OWNER_NAME,
                ExtensionValue::Text("a".repeat(len).into()),
            )
        });
        assert_eq!(result.is_ok(), accepted);
    }

    /// Verifiers must ignore fields they don't recognise, so unknown keys
    /// alongside the PIID or owner name don't invalidate the binding.
    #[test]
    fn tolerates_unknown_mval_keys() {
        let binding = binding_with(|comid| {
            set_mval(
                condition_claim(comid),
                -999,
                ExtensionValue::Text("x".into()),
            );
            set_mval(
                endorsement_claim(comid),
                -999,
                ExtensionValue::Text("x".into()),
            );
        })
        .unwrap();

        assert_eq!(hex::encode(&binding.piid), POE_PIID_HEX);
        assert_eq!(binding.owner_name, "ACME-DC1");
    }
}
