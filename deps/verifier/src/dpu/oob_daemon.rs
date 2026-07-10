// Copyright (c) 2024 Alibaba Cloud
// SPDX-License-Identifier: Apache-2.0

//! Out-of-band (OOB) attestation daemon for the Tri-Secure DPU.
//!
//! Implements the DPU-side OOB attestation daemon described in §5 and §6.

use super::crypto;
use super::error::{VerifierError, VerifierResult};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// Length of a SHA-384 witness digest.
pub const WITNESS_LEN: usize = 48;

/// A bidirectional, host-independent byte channel (models rshim).
pub trait RshimChannel {
    /// Transmits a framed message over the OOB channel.
    fn send(&mut self, data: &[u8]) -> VerifierResult<()>;
    /// Receives the next framed message, or None if the channel is empty.
    fn recv(&mut self) -> VerifierResult<Option<Vec<u8>>>;
}

/// In-process loopback channel.
#[derive(Clone, Default)]
pub struct LoopbackRshim {
    queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
}

impl LoopbackRshim {
    pub fn new() -> Self {
        Self {
            queue: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
    pub fn len(&self) -> usize {
        self.queue.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl RshimChannel for LoopbackRshim {
    fn send(&mut self, data: &[u8]) -> VerifierResult<()> {
        self.queue.lock().unwrap().push_back(data.to_vec());
        Ok(())
    }
    fn recv(&mut self) -> VerifierResult<Option<Vec<u8>>> {
        Ok(self.queue.lock().unwrap().pop_front())
    }
}

/// File-backed channel: models /dev/rshim* device.
pub struct FileRshim {
    path: std::path::PathBuf,
    read_offset: u64,
}

impl FileRshim {
    pub fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            read_offset: 0,
        }
    }
}

impl RshimChannel for FileRshim {
    fn send(&mut self, data: &[u8]) -> VerifierResult<()> {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| VerifierError::OobChannel(format!("open for append: {e}")))?;
        let len = (data.len() as u32).to_be_bytes();
        f.write_all(&len)
            .and_then(|_| f.write_all(data))
            .map_err(|e| VerifierError::OobChannel(format!("write: {e}")))?;
        Ok(())
    }

    fn recv(&mut self) -> VerifierResult<Option<Vec<u8>>> {
        let mut f = match std::fs::File::open(&self.path) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(self.read_offset))
            .map_err(|e| VerifierError::OobChannel(format!("seek: {e}")))?;
        let mut len_buf = [0u8; 4];
        if f.read_exact(&mut len_buf).is_err() {
            return Ok(None);
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        f.read_exact(&mut buf)
            .map_err(|e| VerifierError::OobChannel(format!("short read: {e}")))?;
        self.read_offset += 4 + len as u64;
        Ok(Some(buf))
    }
}

/// The DPU network engine's wire-speed witness.
#[derive(Default)]
pub struct NetworkEngineWitness;

impl NetworkEngineWitness {
    /// Hashes evidence at wire speed as it traverses the engine (witness e_1).
    pub fn witness(&self, evidence: &[u8]) -> Vec<u8> {
        crypto::sha384(evidence)
    }
}

/// On-path pre-verification hook.
pub trait PreVerifier {
    /// Returns Ok(()) iff dpu_evidence passes local pre-verification.
    fn pre_verify(&self, dpu_evidence: &[u8]) -> VerifierResult<()>;
}

/// A closure-backed PreVerifier.
pub struct FnPreVerifier<F: Fn(&[u8]) -> VerifierResult<()>>(pub F);

impl<F: Fn(&[u8]) -> VerifierResult<()>> PreVerifier for FnPreVerifier<F> {
    fn pre_verify(&self, dpu_evidence: &[u8]) -> VerifierResult<()> {
        (self.0)(dpu_evidence)
    }
}

/// The OOB attestation report: E_D || H(E_C) || H(E_G).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OobReport {
    pub dpu_evidence: Vec<u8>,
    pub cpu_witness: Vec<u8>,
    pub gpu_witness: Vec<u8>,
}

impl OobReport {
    /// Serializes to wire framing.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.dpu_evidence.len() + 2 * WITNESS_LEN);
        out.extend_from_slice(&(self.dpu_evidence.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.dpu_evidence);
        out.extend_from_slice(&self.cpu_witness);
        out.extend_from_slice(&self.gpu_witness);
        out
    }

    /// Parses wire framing.
    pub fn from_bytes(data: &[u8]) -> VerifierResult<Self> {
        if data.len() < 4 {
            return Err(VerifierError::OobChannel("truncated report header".into()));
        }
        let ed_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let expected = 4 + ed_len + 2 * WITNESS_LEN;
        if data.len() != expected {
            return Err(VerifierError::OobChannel(format!(
                "report length mismatch: expected {expected}, got {}",
                data.len()
            )));
        }
        let dpu_evidence = data[4..4 + ed_len].to_vec();
        let cpu_witness = data[4 + ed_len..4 + ed_len + WITNESS_LEN].to_vec();
        let gpu_witness = data[4 + ed_len + WITNESS_LEN..].to_vec();
        Ok(Self {
            dpu_evidence,
            cpu_witness,
            gpu_witness,
        })
    }
}

/// The OOB attestation daemon running on the DPU ARM cores.
pub struct OobDaemon<C: RshimChannel> {
    channel: C,
    engine: NetworkEngineWitness,
    dpu_evidence: Vec<u8>,
    pre_verifier: Option<Box<dyn PreVerifier>>,
    forwarded: u64,
    rejected: u64,
}

impl<C: RshimChannel> OobDaemon<C> {
    /// Creates a daemon bound to an rshim channel and its local DICE evidence.
    pub fn new(channel: C, dpu_evidence: Vec<u8>) -> Self {
        Self {
            channel,
            engine: NetworkEngineWitness,
            dpu_evidence,
            pre_verifier: None,
            forwarded: 0,
            rejected: 0,
        }
    }

    /// Creates a daemon with on-path pre-verifier.
    pub fn with_pre_verifier(
        channel: C,
        dpu_evidence: Vec<u8>,
        pre_verifier: Box<dyn PreVerifier>,
    ) -> Self {
        let mut d = Self::new(channel, dpu_evidence);
        d.pre_verifier = Some(pre_verifier);
        d
    }

    pub fn set_pre_verifier(&mut self, pre_verifier: Box<dyn PreVerifier>) {
        self.pre_verifier = Some(pre_verifier);
    }

    pub fn forwarded_count(&self) -> u64 {
        self.forwarded
    }

    pub fn rejected_count(&self) -> u64 {
        self.rejected
    }

    /// Witnesses CPU/GPU evidence and forwards over OOB channel.
    pub fn witness_and_forward(
        &mut self,
        cpu_evidence: &[u8],
        gpu_evidence: &[u8],
    ) -> VerifierResult<OobReport> {
        if cpu_evidence.is_empty() || gpu_evidence.is_empty() {
            return Err(VerifierError::OobChannel(
                "empty in-band evidence at DPU ingress".into(),
            ));
        }

        // On-path pre-verification
        if let Some(pv) = &self.pre_verifier {
            if let Err(e) = pv.pre_verify(&self.dpu_evidence) {
                self.rejected += 1;
                return Err(VerifierError::ChainValidation {
                    layer: "oob_pre_verify".to_string(),
                    reason: format!("on-path pre-verification rejected DPU evidence: {e}"),
                });
            }
        }

        let report = OobReport {
            dpu_evidence: self.dpu_evidence.clone(),
            cpu_witness: self.engine.witness(cpu_evidence),
            gpu_witness: self.engine.witness(gpu_evidence),
        };
        self.channel.send(&report.to_bytes())?;
        self.forwarded += 1;
        Ok(report)
    }

    /// Runs the main loop over a batch of (E_C, E_G) pairs.
    pub fn run_loop(&mut self, pairs: &[(Vec<u8>, Vec<u8>)]) -> VerifierResult<u64> {
        for (ec, eg) in pairs {
            self.witness_and_forward(ec, eg)?;
        }
        Ok(self.forwarded)
    }
}
