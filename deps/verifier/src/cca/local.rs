// Copyright (c) 2023 Arm Ltd.
// Copyright (c) 2025 Linaro Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use anyhow::Result;
use base64::engine::general_purpose;
use ccatoken::store::*;
use ccatoken::token::Evidence;
use config::Config;
use core::result::Result::Ok;
use ear::{Appraisal, Ear, RawValue, VerifierID};
use ear::{Extensions, TrustTier};
use log::debug;
use serde_json::json;
use std::collections::BTreeMap;
use std::{fs, io::Cursor};

pub fn verify(config: Config, token: &Vec<u8>, expected_report_data: &Vec<u8>) -> Result<Ear> {
    debug!("using config: {:?}", config);

    let config::CcaVerifierConfig::Local { ta_store, rv_store } = config.cca_verifier else {
        bail!("expecting local configuration");
    };

    let jta = fs::read_to_string(&ta_store).context("loading TA store")?;
    let jrv = fs::read_to_string(&rv_store).context("loading RV store")?;

    let mut tas: MemoTrustAnchorStore = Default::default();
    tas.load_json(&jta).context(format!(
        "loading trust anchors from JSON store {}",
        ta_store.display()
    ))?;

    let mut rvs: MemoRefValueStore = Default::default();
    rvs.load_json(&jrv).context(format!(
        "loading reference values from JSON store {}",
        rv_store.display()
    ))?;

    let cursor = Cursor::new(token);
    let mut e: Evidence = Evidence::decode(cursor).context("decoding CCA evidence")?;

    e.verify(&tas).context("verifying CCA evidence")?;
    e.appraise(&rvs).context("appraising CCA evidence")?;

    let (platform_tvec, realm_tvec) = e.get_trust_vectors();

    // Check that the Realm token was correctly signed using the RAK and that
    // the RAK was correctly attested.
    if realm_tvec.instance_identity.tier() != TrustTier::Affirming {
        bail!("RAK signature or RAK attestation could not be verified");
    }

    // Check that the challenge in the Realm token matches the expected_report_data
    if *expected_report_data != e.realm_claims.challenge {
        bail!("realm token challenge claim does not match expected_report_data");
    }

    // Synthesize TCB claims the way EAR wants to report them:
    // realm part
    let realm_annotated_evidence =
        realm_annotated_evidence(&e).context("synthesizing CCA Realm TCB claims-set")?;

    let mut realm_appraisal = Appraisal::new();
    realm_appraisal.annotated_evidence = realm_annotated_evidence;
    realm_appraisal.trust_vector = realm_tvec;
    realm_appraisal.update_status_from_trust_vector();

    // platform part
    let platform_annotated_evidence =
        platform_annotated_evidence(&e).context("syntesizing CCA Platform TCB claims-set")?;

    let mut platform_appraisal = Appraisal::new();
    platform_appraisal.annotated_evidence = platform_annotated_evidence;
    platform_appraisal.trust_vector = platform_tvec;
    platform_appraisal.update_status_from_trust_vector();

    let ear = Ear {
        profile: "tag:github.com,2023:veraison/ear".to_string(),
        vid: VerifierID {
            build: "CoCo CCA local verifier".to_string(),
            developer: "https://veraison-project.org".to_string(),
        },
        submods: BTreeMap::from([
            ("CCA_SSD_PLATFORM".to_string(), platform_appraisal),
            ("CCA_REALM".to_string(), realm_appraisal),
        ]),
        iat: 0,                        // not relevant
        nonce: None,                   // not relevant
        raw_evidence: None,            // not relevant
        extensions: Extensions::new(), // not relevant
    };

    Ok(ear)
}

// TODO(tho) why not populating RealmClaims and serialize?
fn realm_annotated_evidence(e: &Evidence) -> Result<BTreeMap<String, RawValue>> {
    // TODO(tho) switch encoding to Base16.
    // See https://github.com/confidential-containers/trustee/issues/372
    let pv = general_purpose::STANDARD.encode(e.realm_claims.perso);
    let rim = general_purpose::STANDARD.encode(e.realm_claims.rim.clone());
    let rem0 = general_purpose::STANDARD.encode(e.realm_claims.rem[0].clone());
    let rem1 = general_purpose::STANDARD.encode(e.realm_claims.rem[1].clone());
    let rem2 = general_purpose::STANDARD.encode(e.realm_claims.rem[2].clone());
    let rem3 = general_purpose::STANDARD.encode(e.realm_claims.rem[3].clone());
    let nonce = general_purpose::STANDARD.encode(e.realm_claims.challenge);
    let hash_algo_id = e.realm_claims.hash_alg.clone();

    // I am making the choice of reporting only the claims that are related to
    // (currently) unvalidate pieces of the TCB.  The assumption is that CCA
    // platform has been already fully validated (including RAK attestation),
    // and that the only piece of TCB that remains to be validated is the Realm.
    let j = json!({
        "cca-realm-challenge": nonce,
        "cca-realm-extensible-measurements": [
            rem0, rem1, rem2, rem3
        ],
        "cca-realm-hash-algo-id": hash_algo_id,
        "cca-realm-initial-measurement": rim,
        "cca-realm-personalization-value": pv
    })
    .to_string();

    let realm_claims = serde_json::from_str(&j)?;

    Ok(realm_claims)
}

fn platform_annotated_evidence(e: &Evidence) -> Result<BTreeMap<String, RawValue>> {
    let instance_id = general_purpose::STANDARD.encode(e.platform_claims.inst_id);
    let implementation_id = general_purpose::STANDARD.encode(e.platform_claims.impl_id);

    // only report class and instance information for the appraised platform
    let j = json!({
        "cca-platform-instance-id": instance_id,
        "cca-platform-implementation-id": implementation_id
    })
    .to_string();

    let platform_claims = serde_json::from_str(&j)?;

    Ok(platform_claims)
}
