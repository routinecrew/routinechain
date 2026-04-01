use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

/// Generate a new Ed25519 keypair
/// Returns (public_key_32bytes, private_key_32bytes)
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key.to_bytes(), signing_key.to_bytes())
}

/// Sign data with Ed25519 private key
pub fn sign(data: &[u8], private_key: &[u8; 32]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(private_key);
    let signature = signing_key.sign(data);
    signature.to_bytes()
}

/// Verify Ed25519 signature
pub fn verify(data: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key.verify(data, &sig).is_ok()
}

/// blake3 hash of data → 32 bytes
pub fn hash(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

/// blake3 hash of multiple data chunks
pub fn hash_concat(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_sign_verify() {
        let (public_key, private_key) = generate_keypair();
        let data = b"hello routinechain";

        let signature = sign(data, &private_key);
        assert!(verify(data, &signature, &public_key));
        assert!(!verify(b"wrong data", &signature, &public_key));
    }

    #[test]
    fn test_hash() {
        let h1 = hash(b"hello");
        let h2 = hash(b"hello");
        let h3 = hash(b"world");

        assert_eq!(h1, h2);
        assert_ne!(h1, h3);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_hash_concat() {
        let h1 = hash_concat(&[b"hello", b"world"]);
        let h2 = hash_concat(&[b"hello", b"world"]);
        let h3 = hash_concat(&[b"helloworld"]);

        assert_eq!(h1, h2);
        // Streaming hash of two chunks should equal hash of concatenated
        assert_eq!(h1, h3);
        assert_eq!(h1.len(), 32);
    }
}
