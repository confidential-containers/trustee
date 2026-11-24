#[cfg(feature = "coco-as-grpc")]
pub mod grpc;

#[cfg(any(feature = "coco-as-builtin", feature = "coco-as-builtin-no-verifier"))]
pub mod builtin;

/// Attestation Service policies applied when a client does not select a
/// attestation-policy-selector. These are the built-in policies of the
/// Attestation Service, each judges the results of its own devices and
/// produces its own entry in the token.
pub const DEFAULT_POLICY_IDS: [&str; 4] = [
    "default_cpu",
    "default_gpu",
    "default_switch",
    "default_ppcie",
];
