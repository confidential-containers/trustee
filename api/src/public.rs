// Copyright (c) 2023 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use super::*;

macro_rules! internal {
    ($reason: expr) => {
        return HttpResponse::InternalServerError()
            .message_body(BoxBody::new($reason))
            .unwrap()
    };
}

/// GET /token-certificate-chain
pub async fn get_token_certificate(
    token_broker: web::Data<Arc<RwLock<dyn AttestationTokenBroker + Send + Sync>>>,
) -> HttpResponse {
    match token_broker.read().await.x509_certificate_chain() {
        Ok(cert) => HttpResponse::Ok()
            .content_type("application/json")
            .body(cert),
        Err(e) => internal!(format!("Get token certificate failed: {e}")),
    }
}
