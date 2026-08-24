// Copyright (c) 2026 by Alibaba.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

use kbs_types::{Tee, TeePubKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Trust Context is an overall abstraction upon different backend
/// attestation services. This lets KBS keep a single policy to filter
/// heterogeneous attestation results. The context is a general
/// representation of the attestation result for a given TEE env and is
/// used as a "passport" to access different KBS plugins.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TrustContext {
    /// Backend-agnostic summary of the attestation result, including whether
    /// verification succeeded and the normalized token claims exposed to policy.
    pub attestation_summary: AttestationSummary,

    /// Public key of the attested TEE, extracted from runtime data. KBS uses
    /// this to encrypt secrets delivered to the guest (JWE).
    pub tee_pubkey: TeePubKey,

    /// Backend-specific extensions attached to the attestation result that are
    /// not part of the standard token schema (e.g. policy-defined appraisal
    /// extensions in a CoCo AS EAR token). The structure is backend-defined;
    /// for CoCo AS this is a map of submodule name to non-`ear.*` claims.
    pub custom_claims: Value,
}

/// The backend-agnostic abstraction of an attestation result. This hides the
/// different token formats of backend attestation services and provides a
/// unified interface to the KBS policy engine and plugins.
#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct AttestationSummary {
    /// The TEE type(s) that the evidence has been attested for.
    pub tee_type: Vec<Tee>,

    /// The attestation policy identifiers that have been evaluated.
    pub policy_ids: Vec<String>,

    /// Identity of the attestation service that issued this result, taken from
    /// the verified token (typically its `iss` claim). This distinguishes
    /// different operators of the same kind of attestation service and is
    /// cryptographically bound to the token signature.
    pub issuer: Option<String>,

    /// Whether the backend attestation service affirmed the evidence.
    pub verification_result: bool,

    /// The full set of claims carried by the backend attestation token. KBS
    /// only requires `verification_result` for the common allow/deny decision,
    /// but the raw claims are retained here so that advanced policies can drill
    /// down into TEE-specific details (e.g. measurements or TCB status) without
    /// having to understand each backend's token format.
    pub claims: Value,
}
