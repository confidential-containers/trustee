use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384, Sha512};
use sm3::Sm3;
use strum::{AsRefStr, Display, EnumString};

#[cfg(all(feature = "alloc", not(feature = "std")))]
use alloc::{vec, vec::Vec};

/// Hash algorithms used to calculate runtime/init data binding
#[derive(
    Debug, Clone, Copy, PartialEq, Serialize, Deserialize, AsRefStr, Display, EnumString, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum HashAlgorithm {
    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha256")]
    Sha256,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha384")]
    #[default]
    Sha384,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sha512")]
    Sha512,

    #[strum(ascii_case_insensitive)]
    #[strum(serialize = "sm3")]
    Sm3,
}

fn hash_reportdata<D: Digest>(material: &[u8]) -> Vec<u8> {
    D::new().chain_update(material).finalize().to_vec()
}

impl HashAlgorithm {
    /// Return the hash value length in bytes
    pub fn digest_len(&self) -> usize {
        match self {
            HashAlgorithm::Sha256 => 32,
            HashAlgorithm::Sha384 => 48,
            HashAlgorithm::Sha512 => 64,
            HashAlgorithm::Sm3 => 32,
        }
    }

    pub fn digest(&self, material: &[u8]) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha256 => hash_reportdata::<Sha256>(material),
            HashAlgorithm::Sha384 => hash_reportdata::<Sha384>(material),
            HashAlgorithm::Sha512 => hash_reportdata::<Sha512>(material),
            HashAlgorithm::Sm3 => hash_reportdata::<Sm3>(material),
        }
    }

    /// Return a list of all supported hash algorithms.
    pub fn list_all() -> Vec<Self> {
        vec![
            HashAlgorithm::Sha256,
            HashAlgorithm::Sha384,
            HashAlgorithm::Sha512,
            HashAlgorithm::Sm3,
        ]
    }
}
