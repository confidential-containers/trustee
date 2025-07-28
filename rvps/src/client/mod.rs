// Copyright (c) 2025 IBM
//
// SPDX-License-Identifier: Apache-2.0
//
// Helpers for building a client for the RVPS

use anyhow::*;

use crate::rvps_api::reference::{
    reference_value_provider_service_client::ReferenceValueProviderServiceClient,
    ReferenceValueQueryRequest, ReferenceValueRegisterRequest,
};

pub async fn register(address: String, message: String) -> Result<()> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueRegisterRequest { message });

    client.register_reference_value(req).await?;

    Ok(())
}

pub async fn query(address: String, reference_value_id: String) -> Result<String> {
    let mut client = ReferenceValueProviderServiceClient::connect(address).await?;
    let req = tonic::Request::new(ReferenceValueQueryRequest { reference_value_id });

    let rvs = client
        .query_reference_value(req)
        .await?
        .into_inner()
        .reference_value_results;

    Ok(rvs)
}
