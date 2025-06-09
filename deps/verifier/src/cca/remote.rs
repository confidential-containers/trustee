// Copyright (c) 2023 Arm Ltd.
// Copyright (c) 2025 Linaro Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;
use anyhow::Result;
use base64::Engine;
use config::Config;
use core::result::Result::Ok;
use ear::Ear;
use log::{debug, error};
use std::str;

const MEDIA_TYPE: &str = r#"application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0""#;

fn evidence_builder(
    nonce: &[u8],
    accept: &[String],
    token: Vec<u8>,
) -> Result<(Vec<u8>, String), veraison_apiclient::Error> {
    debug!("server challenge: {:?}", nonce);
    debug!("acceptable media types: {:#?}", accept);
    // TODO: Get the CCA media type from the slice of `accept`.
    Ok((token, MEDIA_TYPE.to_string()))
}

pub async fn verify(config: Config, token: &[u8], expected_report_data: &Vec<u8>) -> Result<Ear> {
    debug!("using config: {:?}", config);

    let config::CcaVerifierConfig::Remote { address, ca_cert } = config.cca_verifier else {
        bail!("expecting remote configuration");
    };

    let mut disco_builder = DiscoveryBuilder::new().with_base_url(address.clone());

    if let Some(ref ca_cert) = ca_cert {
        disco_builder = disco_builder.with_root_certificate(ca_cert.clone())
    }

    let disco = disco_builder
        .build()
        .context("Failed to start API discovery with the service")?;

    let verification_api = disco
        .get_verification_api()
        .await
        .context("Failed to discover the verification endpoint details")?;

    let relpath = verification_api
        .get_api_endpoint("newChallengeResponseSession")
        .context("Could not locate a newChallengeResponseSession endpoint")?;

    let api_endpoint = format!("{}{}", address, relpath);

    let mut cr_builder = ChallengeResponseBuilder::new().with_new_session_url(api_endpoint);

    if let Some(ref ca_cert) = ca_cert {
        cr_builder = cr_builder.with_root_certificate(ca_cert.clone())
    }

    let cr = cr_builder
        .build()
        .context("Failed to start challenge-response API with the service")?;

    let n = Nonce::Value(expected_report_data.clone());

    let result = match cr.run(n, evidence_builder, token.to_owned()).await {
        Err(e) => {
            error!("Error: {}", e);
            bail!("remote verification failed with error: {:?}", e);
        }
        Ok(attestation_result) => attestation_result,
    };

    let verifier_pkey = verification_api.ear_verification_key_as_string();

    let plain_ear = Ear::from_jwt_jwk(
        result.as_str(),
        ear::Algorithm::ES256,
        verifier_pkey.as_bytes(),
    )
    .context("decrypting EAR with the decoding key")?;

    if let Some(ref ear_nonce) = plain_ear.nonce {
        let nonce_byte = base64::engine::general_purpose::URL_SAFE
            .decode(ear_nonce.to_string())
            .context("base64-decoding nonce from EAR")?;

        if *expected_report_data != nonce_byte {
            bail!(
                "nonce verification failed: want {:02x?}, got {:02x?}",
                *expected_report_data,
                nonce_byte
            );
        }
    } else {
        bail!("no nonce found in EAR")
    }

    Ok(plain_ear)
}
