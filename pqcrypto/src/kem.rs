// STATUS: 100% — ML-KEM-768 encapsulate/decapsulate via liboqs
// pqcrypto/src/kem.rs
// GhostIT C11 — ML-KEM-768 (CRYSTALS-Kyber) Key Encapsulation
// NIST PQC Standard 2024 — quantum-resistant key exchange
// Ghost Layer Technologies · Chennai · June 2026

use oqs::kem::{Kem, Algorithm};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KemError {
    #[error("OQS error: {0}")]
    Oqs(String),
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
}

/// ML-KEM-768 key pair (public + secret)
pub struct KemKeyPair {
    pub public_key:  Vec<u8>,
    pub secret_key:  Vec<u8>,
}

/// ML-KEM-768 wrapper around liboqs
pub struct MlKem768 {
    kem: Kem,
}

impl MlKem768 {
    /// Create a new ML-KEM-768 instance
    pub fn new() -> Result<Self, KemError> {
        let kem = Kem::new(Algorithm::Kyber768)
            .map_err(|e| KemError::Oqs(e.to_string()))?;
        Ok(Self { kem })
    }

    /// Generate a fresh key pair
    pub fn generate_keypair(&self) -> Result<KemKeyPair, KemError> {
        let (pk, sk) = self.kem.keypair()
            .map_err(|e| KemError::Oqs(e.to_string()))?;
        Ok(KemKeyPair {
            public_key: pk.into_vec(),
            secret_key: sk.into_vec(),
        })
    }

    /// Encapsulate — sender calls this with recipient public key
    /// Returns (ciphertext, shared_secret)
    pub fn encapsulate(
        &self,
        public_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), KemError> {
        let pk = self.kem.public_key_from_bytes(public_key)
            .ok_or(KemError::InvalidKeyLength)?;

        let (ciphertext, shared_secret) = self.kem.encapsulate(&pk)
            .map_err(|e| KemError::Oqs(e.to_string()))?;

        Ok((ciphertext.into_vec(), shared_secret.into_vec()))
    }

    /// Decapsulate — recipient calls this with their secret key + ciphertext
    /// Returns shared_secret (must match encapsulate output)
    pub fn decapsulate(
        &self,
        secret_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KemError> {
        let sk = self.kem.secret_key_from_bytes(secret_key)
            .ok_or(KemError::InvalidKeyLength)?;
        let ct = self.kem.ciphertext_from_bytes(ciphertext)
            .ok_or(KemError::InvalidKeyLength)?;

        let shared_secret = self.kem.decapsulate(&sk, &ct)
            .map_err(|_| KemError::DecapsulationFailed)?;

        Ok(shared_secret.into_vec())
    }

    /// Public key length in bytes (ML-KEM-768 = 1184 bytes)
    pub fn public_key_len(&self) -> usize {
        self.kem.length_public_key()
    }

    /// Ciphertext length in bytes (ML-KEM-768 = 1088 bytes)
    pub fn ciphertext_len(&self) -> usize {
        self.kem.length_ciphertext()
    }

    /// Shared secret length in bytes (ML-KEM-768 = 32 bytes)
    pub fn shared_secret_len(&self) -> usize {
        self.kem.length_shared_secret()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mlkem768_roundtrip() {
        let kem = MlKem768::new().unwrap();
        let kp  = kem.generate_keypair().unwrap();

        let (ct, ss_enc) = kem.encapsulate(&kp.public_key).unwrap();
        let ss_dec = kem.decapsulate(&kp.secret_key, &ct).unwrap();

        assert_eq!(ss_enc, ss_dec, "Shared secrets must match");
        assert_eq!(ss_enc.len(), 32, "ML-KEM-768 shared secret is 32 bytes");
        println!("ML-KEM-768 roundtrip OK — shared secret: {}",
            hex::encode(&ss_enc));
    }

    #[test]
    fn test_key_lengths() {
        let kem = MlKem768::new().unwrap();
        assert_eq!(kem.public_key_len(), 1184);
        assert_eq!(kem.ciphertext_len(), 1088);
        assert_eq!(kem.shared_secret_len(), 32);
    }
}
