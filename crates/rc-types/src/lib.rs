pub mod block;
pub mod transaction;
pub mod state;
pub mod config;

pub use block::*;
pub use transaction::*;
pub use state::*;
pub use config::*;

/// 32-byte identifier used throughout the system
pub type Id = [u8; 32];

/// 32-byte blake3 hash
pub type Hash = [u8; 32];

/// Empty hash constant (all zeros)
pub const EMPTY_HASH: Hash = [0u8; 32];

/// 64-byte Ed25519 signature (serde-compatible wrapper)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; 64]);

impl serde::Serialize for Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = serde::Deserialize::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Signature must be 64 bytes"));
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&bytes);
        Ok(Signature(arr))
    }
}

impl Default for Signature {
    fn default() -> Self {
        Signature([0u8; 64])
    }
}
