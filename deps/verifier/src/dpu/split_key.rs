// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Split-key receiver for the Tri-Secure DPU-mediated key delivery.
//!
//! Implements the split-key mechanism described in §5/§8.

use super::crypto;
use super::error::{VerifierError, VerifierResult};
use super::oob_daemon::RshimChannel;

/// Length of a key share / assembled key (256 bits).
pub const SHARE_LEN: usize = 32;

/// A single key share tagged with the channel it is expected on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyShare {
    pub bytes: [u8; SHARE_LEN],
}

impl KeyShare {
    pub fn new(bytes: [u8; SHARE_LEN]) -> Self {
        Self { bytes }
    }
    /// Parses a share from a byte slice of exactly SHARE_LEN.
    pub fn from_slice(data: &[u8]) -> VerifierResult<Self> {
        if data.len() != SHARE_LEN {
            return Err(VerifierError::SplitKey(format!(
                "share must be {SHARE_LEN} bytes, got {}",
                data.len()
            )));
        }
        let mut b = [0u8; SHARE_LEN];
        b.copy_from_slice(data);
        Ok(Self { bytes: b })
    }
}

/// A mock RCAR guest-side delivery channel (Trustee KBS → CoCo guest).
#[derive(Default)]
pub struct GuestChannel {
    pending: Option<KeyShare>,
}

impl GuestChannel {
    pub fn new() -> Self {
        Self { pending: None }
    }
    /// The KBS wraps and delivers the guest share after RCAR attestation.
    pub fn deliver(&mut self, share: KeyShare) {
        self.pending = Some(share);
    }
    /// The guest agent receives the pending share.
    pub fn receive(&mut self) -> VerifierResult<KeyShare> {
        self.pending
            .take()
            .ok_or_else(|| VerifierError::SplitKey("no guest share delivered (RCAR)".into()))
    }
}

/// Splits a session key K into a guest share and a DPU share.
/// K = s_g XOR s_d. Returns (guest_share, dpu_share).
pub fn split_key(key: &[u8; SHARE_LEN], dpu_random: &[u8; SHARE_LEN]) -> (KeyShare, KeyShare) {
    let mut guest = [0u8; SHARE_LEN];
    for i in 0..SHARE_LEN {
        guest[i] = key[i] ^ dpu_random[i];
    }
    (KeyShare::new(guest), KeyShare::new(*dpu_random))
}

/// Computes the key-check value: KCV = HMAC-SHA384(K, "tri-secure-kcv" || sid).
pub fn key_check_value(assembled: &[u8; SHARE_LEN], session_id: &str) -> Vec<u8> {
    let mut msg = b"tri-secure-kcv".to_vec();
    msg.extend_from_slice(session_id.as_bytes());
    crypto::hmac_sha384(assembled, &msg).expect("HMAC over fixed-length key")
}

/// Derives the working session key via HKDF-style expansion.
pub fn derive_session_key(assembled: &[u8; SHARE_LEN], session_id: &str) -> [u8; SHARE_LEN] {
    let mut info = b"tri-secure-session".to_vec();
    info.extend_from_slice(session_id.as_bytes());
    let okm = crypto::hmac_sha384(assembled, &info).expect("HKDF-expand");
    let mut key = [0u8; SHARE_LEN];
    key.copy_from_slice(&okm[..SHARE_LEN]);
    key
}

/// The split-key receiver.
pub struct SplitKeyReceiver<C: RshimChannel> {
    session_id: String,
    dpu_channel: C,
    guest_share: Option<KeyShare>,
    dpu_share: Option<KeyShare>,
    expected_kcv: Vec<u8>,
}

impl<C: RshimChannel> SplitKeyReceiver<C> {
    pub fn new(session_id: impl Into<String>, dpu_channel: C, expected_kcv: Vec<u8>) -> Self {
        Self {
            session_id: session_id.into(),
            dpu_channel,
            guest_share: None,
            dpu_share: None,
            expected_kcv,
        }
    }

    /// Receives the guest (RCAR) share.
    pub fn receive_guest_share(&mut self, guest: &mut GuestChannel) -> VerifierResult<()> {
        self.guest_share = Some(guest.receive()?);
        Ok(())
    }

    /// Receives the DPU (rshim) share from the OOB channel.
    pub fn receive_dpu_share(&mut self) -> VerifierResult<()> {
        let raw = self
            .dpu_channel
            .recv()?
            .ok_or_else(|| VerifierError::SplitKey("no DPU share on rshim".into()))?;
        self.dpu_share = Some(KeyShare::from_slice(&raw)?);
        Ok(())
    }

    /// Returns true once both shares are present.
    pub fn is_ready(&self) -> bool {
        self.guest_share.is_some() && self.dpu_share.is_some()
    }

    /// Assembles K = s_g XOR s_d, verifies KCV, returns derived session key.
    pub fn assemble(&self) -> VerifierResult<[u8; SHARE_LEN]> {
        let g = self
            .guest_share
            .as_ref()
            .ok_or_else(|| VerifierError::SplitKey("guest share missing".into()))?;
        let d = self
            .dpu_share
            .as_ref()
            .ok_or_else(|| VerifierError::SplitKey("DPU share missing".into()))?;

        let mut assembled = [0u8; SHARE_LEN];
        for i in 0..SHARE_LEN {
            assembled[i] = g.bytes[i] ^ d.bytes[i];
        }

        let kcv = key_check_value(&assembled, &self.session_id);
        if !ct_eq(&kcv, &self.expected_kcv) {
            return Err(VerifierError::SplitKey(
                "key-check value mismatch (torn or wrong share)".into(),
            ));
        }

        Ok(derive_session_key(&assembled, &self.session_id))
    }
}

/// Constant-time equality for equal-length byte slices.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
