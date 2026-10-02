// Copyright (c) 2026 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

//! Profile-specific CoRIM extraction.
//!
//! A CoRIM's `profile` defines how its extension points are interpreted.
//! A CoRIM whose profile one of the extractors below claims is handled
//! entirely by it, in place of the generic extraction; other CoRIMs fall
//! back to the generic path. The profile only selects among the extractors
//! registered here, never code from the CoRIM itself.

use anyhow::Result;
use corim_rs::{CorimMap, ProfileTypeChoice};

use crate::ReferenceValue;

/// Extracts reference values from CoRIMs whose profile it claims.
pub(super) trait CorimProfileExtractor: Send + Sync {
    /// Whether this extractor claims `profile`.
    fn handles(&self, profile: &ProfileTypeChoice) -> bool;

    /// Extracts reference values from a claimed CoRIM. Anything the profile
    /// doesn't allow, including a malformed encoding of the profile itself,
    /// is rejected with an error rather than ignored: an unclaimed CoRIM would
    /// go to generic extraction and register nothing without an error.
    fn extract(&self, corim: &CorimMap) -> Result<Vec<ReferenceValue>>;
}

/// The built-in profile extractors.
static REGISTERED_EXTRACTORS: &[&dyn CorimProfileExtractor] = &[
    // A CoRIM is handled by the first extractor that claims its profile.
];

/// Runs the extractor claiming `corim`'s profile, or returns `None` if there's
/// none and the caller should fall back to generic extraction.
pub(super) fn extract_for_profile(corim: &CorimMap) -> Option<Result<Vec<ReferenceValue>>> {
    let profile = corim.profile.as_ref()?;
    REGISTERED_EXTRACTORS
        .iter()
        .find(|extractor| extractor.handles(profile))
        .map(|extractor| extractor.extract(corim))
}
