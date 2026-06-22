// STATUS: 100% — X25519 + ML-KEM-768 hybrid KEM, HKDF-SHA-256 key derivation,
//                AES-256-GCM session key, encrypt/decrypt helpers
// pqcrypto/src/hybrid.rs
// GhostIT C11 — Hybrid Post-Quantum KEM
// X25519 (classical) + ML-KEM-768 (quantum-resistant) → HKDF → AES-256-GCM
// Attacker must break BOTH to intercept. Defense in depth.
// Ghost Layer Technologies · Chennai · June 2026

use crate::kem::{MlKem768, KemKeyPair, KemError};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use hkdf::Hkdf;
use sha2::Sha256;
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use rand::RngCore;
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Debug, Error)]
pub enum HybridError {
    #[error("KEM error: {0}")]
    Kem(#[from] KemError),
    #[error("HKDF expand failed")]
    HkdfExpand,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed — possible tampering")]
    DecryptionFailed,
    #[error("Invalid key material")]
    InvalidKey,
}

/// Combined public key for hybrid KEM handshake
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HybridPublicKey {
    pub x25519_pk:  Vec<u8>,   // 32 bytes
    pub mlkem_pk:   Vec<u8>,   // 1184 bytes
}

/// Combined secret key (kept private, never transmitted)
pub struct HybridSecretKey {
    pub x25519_sk:  StaticSecret,
    pub mlkem_sk:   Vec<u8>,
}

/// Key pair for hybrid KEM
pub struct HybridKeyPair {
    pub public_key: HybridPublicKey,
    pub secret_key: HybridSecretKey,
}

/// Encapsulated shared secret sent from initiator to responder
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HybridCiphertext {
    pub x25519_ephemeral_pk: Vec<u8>,   // 32 bytes
    pub mlkem_ciphertext:    Vec<u8>,   // 1088 bytes
}

/// Derived 32-byte session key ready for AES-256-GCM
#[derive(Clone)]
pub struct HybridSharedSecret {
    pub key_bytes: [u8; 32],
}

impl HybridSharedSecret {
    /// Encrypt a plaintext message with AES-256-GCM
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, HybridError> {
        let key    = Key::<Aes256Gcm>::from_slice(&self.key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|_| HybridError::EncryptionFailed)?;

        // Prepend 12-byte nonce to ciphertext
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decrypt a message encrypted with encrypt()
    pub fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, HybridError> {
        if data.len() < 12 {
            return Err(HybridError::DecryptionFailed);
        }
        let (nonce_bytes, ciphertext) = data.split_at(12);
        let key    = Key::<Aes256Gcm>::from_slice(&self.key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce  = Nonce::from_slice(nonce_bytes);

        cipher.decrypt(nonce, ciphertext)
            .map_err(|_| HybridError::DecryptionFailed)
    }
}

/// Main hybrid KEM — orchestrates X25519 + ML-KEM-768 + HKDF
pub struct HybridKem {
    mlkem: MlKem768,
}

impl HybridKem {
    pub fn new() -> Result<Self, HybridError> {
        Ok(Self {
            mlkem: MlKem768::new()?,
        })
    }

    /// Generate a hybrid key pair (call once per endpoint)
    pub fn generate_keypair(&self) -> Result<HybridKeyPair, HybridError> {
        // X25519 key pair
        let x25519_sk  = StaticSecret::random_from_rng(OsRng);
        let x25519_pk  = X25519PublicKey::from(&x25519_sk);

        // ML-KEM-768 key pair
        let mlkem_kp: KemKeyPair = self.mlkem.generate_keypair()?;

        Ok(HybridKeyPair {
            public_key: HybridPublicKey {
                x25519_pk: x25519_pk.as_bytes().to_vec(),
                mlkem_pk:  mlkem_kp.public_key,
            },
            secret_key: HybridSecretKey {
                x25519_sk,
                mlkem_sk: mlkem_kp.secret_key,
            },
        })
    }

    /// Encapsulate — initiator calls this with responder public key
    /// Returns (ciphertext_to_send, shared_secret_for_session)
    pub fn encapsulate(
        &self,
        recipient_pk: &HybridPublicKey,
    ) -> Result<(HybridCiphertext, HybridSharedSecret), HybridError> {
        // ── X25519 DH ────────────────────────────────────────────────────
        let ephemeral_sk  = EphemeralSecret::random_from_rng(OsRng);
        let ephemeral_pk  = X25519PublicKey::from(&ephemeral_sk);

        let recipient_x25519 = {
            let bytes: [u8; 32] = recipient_pk.x25519_pk.as_slice()
                .try_into().map_err(|_| HybridError::InvalidKey)?;
            X25519PublicKey::from(bytes)
        };
        let x25519_shared = ephemeral_sk.diffie_hellman(&recipient_x25519);

        // ── ML-KEM-768 ────────────────────────────────────────────────────
        let (mlkem_ct, mlkem_ss) = self.mlkem.encapsulate(&recipient_pk.mlkem_pk)?;

        // ── HKDF-SHA-256: combine both shared secrets → 32-byte session key ──
        let session_key = Self::derive_key(
            x25519_shared.as_bytes(),
            &mlkem_ss,
        )?;

        Ok((
            HybridCiphertext {
                x25519_ephemeral_pk: ephemeral_pk.as_bytes().to_vec(),
                mlkem_ciphertext:    mlkem_ct,
            },
            HybridSharedSecret { key_bytes: session_key },
        ))
    }

    /// Decapsulate — responder calls this with their secret key + received ciphertext
    pub fn decapsulate(
        &self,
        secret_key:  &HybridSecretKey,
        ciphertext:  &HybridCiphertext,
    ) -> Result<HybridSharedSecret, HybridError> {
        // ── X25519 DH ────────────────────────────────────────────────────
        let ephemeral_pk = {
            let bytes: [u8; 32] = ciphertext.x25519_ephemeral_pk.as_slice()
                .try_into().map_err(|_| HybridError::InvalidKey)?;
            X25519PublicKey::from(bytes)
        };
        let x25519_shared = secret_key.x25519_sk.diffie_hellman(&ephemeral_pk);

        // ── ML-KEM-768 ────────────────────────────────────────────────────
        let mlkem_ss = self.mlkem.decapsulate(
            &secret_key.mlkem_sk,
            &ciphertext.mlkem_ciphertext,
        )?;

        // ── HKDF-SHA-256 ─────────────────────────────────────────────────
        let session_key = Self::derive_key(
            x25519_shared.as_bytes(),
            &mlkem_ss,
        )?;

        Ok(HybridSharedSecret { key_bytes: session_key })
    }

    /// HKDF-SHA-256: IKM = X25519_secret || ML-KEM_secret → 32-byte OKM
    fn derive_key(
        x25519_ss: &[u8],
        mlkem_ss:  &[u8],
    ) -> Result<[u8; 32], HybridError> {
        // Concatenate both shared secrets as IKM
        let mut ikm = Vec::with_capacity(x25519_ss.len() + mlkem_ss.len());
        ikm.extend_from_slice(x25519_ss);
        ikm.extend_from_slice(mlkem_ss);

        let hkdf = Hkdf::<Sha256>::new(
            Some(b"ghostit-c11-hybrid-kem-v1"),  // salt
            &ikm,
        );

        let mut okm = [0u8; 32];
        hkdf.expand(b"ghostit-session-key", &mut okm)
            .map_err(|_| HybridError::HkdfExpand)?;

        Ok(okm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_kem_roundtrip() {
        let kem = HybridKem::new().unwrap();

        // Responder generates key pair and shares public key
        let responder_kp = kem.generate_keypair().unwrap();

        // Initiator encapsulates
        let (ct, ss_init) = kem.encapsulate(&responder_kp.public_key).unwrap();

        // Responder decapsulates
        let ss_resp = kem.decapsulate(&responder_kp.secret_key, &ct).unwrap();

        assert_eq!(ss_init.key_bytes, ss_resp.key_bytes,
            "Session keys must match");
        println!("Hybrid KEM roundtrip OK — session key: {}",
            hex::encode(ss_init.key_bytes));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let kem = HybridKem::new().unwrap();
        let kp  = kem.generate_keypair().unwrap();
        let (ct, ss) = kem.encapsulate(&kp.public_key).unwrap();
        let ss2 = kem.decapsulate(&kp.secret_key, &ct).unwrap();

        let plaintext  = b"GhostIT C11 — harvest-now-decrypt-later defeated";
        let encrypted  = ss.encrypt(plaintext).unwrap();
        let decrypted  = ss2.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        println!("AES-256-GCM encrypt/decrypt OK");
    }
}
