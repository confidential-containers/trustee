// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Cross-chip evidence binder for the Tri-Secure tri-core attestation protocol.
//!
//! Implements the binding-nonce construction and the atomic TriCoreBundle
//! verification described in Tri-Secure paper §6.

use super::crypto;
use super::error::{VerifierError, VerifierResult};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Length in bytes of a single per-chip nonce (256 bits).
pub const NONCE_LEN: usize = 32;
/// Length in bytes of the concatenated binding nonce B = N_T || N_D || N_C.
pub const BINDING_LEN: usize = 3 * NONCE_LEN;
/// Length in bytes of a SHA-384 digest.
pub const DIGEST_LEN: usize = 48;

/// The three per-chip binding nonces (N_T, N_D, N_C).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingNonce {
    pub n_t: [u8; NONCE_LEN],
    pub n_d: [u8; NONCE_LEN],
    pub n_c: [u8; NONCE_LEN],
}

impl BindingNonce {
    /// Draws a fresh binding nonce from a cryptographically secure RNG.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut n_t = [0u8; NONCE_LEN];
        let mut n_d = [0u8; NONCE_LEN];
        let mut n_c = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut n_t);
        rng.fill_bytes(&mut n_d);
        rng.fill_bytes(&mut n_c);
        Self { n_t, n_d, n_c }
    }

    /// Convenience constructor drawing from the OS CSPRNG.
    pub fn generate_os() -> Self {
        Self::generate(&mut rand_core::OsRng)
    }

    /// Returns B = N_T || N_D || N_C (768 bits / 96 bytes).
    pub fn binding_bytes(&self) -> [u8; BINDING_LEN] {
        let mut b = [0u8; BINDING_LEN];
        b[..NONCE_LEN].copy_from_slice(&self.n_t);
        b[NONCE_LEN..2 * NONCE_LEN].copy_from_slice(&self.n_d);
        b[2 * NONCE_LEN..].copy_from_slice(&self.n_c);
        b
    }

    /// Returns H(B) (SHA-384, 48 bytes).
    pub fn combined_hash(&self) -> Vec<u8> {
        crypto::sha384(&self.binding_bytes())
    }

    /// Rejects a degenerate (all-zero) nonce.
    pub fn is_nonzero(&self) -> bool {
        !(self.n_t.iter().all(|&b| b == 0)
            && self.n_d.iter().all(|&b| b == 0)
            && self.n_c.iter().all(|&b| b == 0))
    }
}

/// Which chip produced an evidence blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChipKind {
    Cpu,
    Gpu,
    Dpu,
}

/// A single chip's attestation evidence, tagged with binding-nonce commitment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChipEvidence {
    pub kind: ChipKind,
    /// Raw evidence bytes.
    pub evidence: Vec<u8>,
    /// The H(B) the chip committed to (48 bytes).
    pub bound_nonce_hash: Vec<u8>,
}

impl ChipEvidence {
    /// Builds an evidence blob that correctly commits to the binding nonce.
    pub fn bound(kind: ChipKind, evidence: Vec<u8>, nonce: &BindingNonce) -> Self {
        Self {
            kind,
            evidence,
            bound_nonce_hash: nonce.combined_hash(),
        }
    }
}

/// The aggregate of all three chip evidences plus the session binding nonce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriCoreBundle {
    pub session_id: String,
    pub binding_nonce: BindingNonce,
    pub cpu: ChipEvidence,
    pub gpu: ChipEvidence,
    pub dpu: ChipEvidence,
}

/// The cross-chip binder.
pub struct TriCoreBinder;

impl TriCoreBinder {
    /// Opens a new attestation session.
    pub fn new_session<R: RngCore + CryptoRng>(rng: &mut R) -> BindingNonce {
        BindingNonce::generate(rng)
    }

    /// Assembles a TriCoreBundle from three chip evidences.
    pub fn assemble(
        session_id: impl Into<String>,
        binding_nonce: BindingNonce,
        cpu_evidence: Vec<u8>,
        gpu_evidence: Vec<u8>,
        dpu_evidence: Vec<u8>,
    ) -> TriCoreBundle {
        TriCoreBundle {
            session_id: session_id.into(),
            cpu: ChipEvidence::bound(ChipKind::Cpu, cpu_evidence, &binding_nonce),
            gpu: ChipEvidence::bound(ChipKind::Gpu, gpu_evidence, &binding_nonce),
            dpu: ChipEvidence::bound(ChipKind::Dpu, dpu_evidence, &binding_nonce),
            binding_nonce,
        }
    }

    /// Atomically verifies cross-chip binding (Theorem 2).
    pub fn verify_binding(bundle: &TriCoreBundle) -> VerifierResult<()> {
        if !bundle.binding_nonce.is_nonzero() {
            return Err(VerifierError::BindingFailed(
                "binding nonce is all zeros (possible replay)".into(),
            ));
        }

        let expected = bundle.binding_nonce.combined_hash();

        for ev in [&bundle.cpu, &bundle.gpu, &bundle.dpu] {
            if ev.evidence.is_empty() {
                return Err(VerifierError::BindingFailed(format!(
                    "{:?} evidence is empty",
                    ev.kind
                )));
            }
            if ev.bound_nonce_hash.len() != DIGEST_LEN {
                return Err(VerifierError::BindingFailed(format!(
                    "{:?} binding commitment must be {} bytes, got {}",
                    ev.kind,
                    DIGEST_LEN,
                    ev.bound_nonce_hash.len()
                )));
            }
            if ev.bound_nonce_hash != expected {
                return Err(VerifierError::BindingFailed(format!(
                    "{:?} evidence is bound to a different session (nonce mismatch)",
                    ev.kind
                )));
            }
        }

        Ok(())
    }
}
