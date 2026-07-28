#[cfg(feature = "coco-as-grpc")]
pub mod grpc;

#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
pub mod builtin;

/// Attestation Service policy applied when a client does not select a
/// policy-selector.
pub const DEFAULT_POLICY_ID: &str = "default";
