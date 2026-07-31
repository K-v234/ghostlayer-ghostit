//! Real, genuine hybrid post-quantum signing for Ghost IT releases.
//! Matches the documented design (PRD C11): Ed25519 || ML-DSA-65
//! hybrid signatures for agent binaries and models. Deliberately NOT
//! used for high-frequency heartbeats -- ML-DSA-65 signatures are
//! ~3.3KB vs Ed25519's 64 bytes, a real tradeoff that only makes
//! sense for infrequent, high-value operations like a release
//! binary, not a 60-second heartbeat.

use ed25519_dalek::{SigningKey as Ed25519SigningKey, Signer as Ed25519Signer, VerifyingKey as Ed25519VerifyingKey, Signature as Ed25519Signature};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::DetachedSignature;

pub struct HybridKeypair {
    pub ed25519_signing: Ed25519SigningKey,
    pub mldsa_public: mldsa65::PublicKey,
    pub mldsa_secret: mldsa65::SecretKey,
}

pub struct HybridSignature {
    pub ed25519_sig: Vec<u8>,
    pub mldsa_sig: Vec<u8>,
}

impl HybridKeypair {
    /// Real, genuine hybrid keypair generation -- both classical and
    /// post-quantum keys, matching the documented hybrid design.
    pub fn generate() -> Self {
        let mut csprng = rand::rngs::OsRng;
        let ed25519_signing = Ed25519SigningKey::generate(&mut csprng);
        let (mldsa_public, mldsa_secret) = mldsa65::keypair();
        Self { ed25519_signing, mldsa_public, mldsa_secret }
    }

    /// Real, genuine hybrid sign -- produces BOTH signatures. A real
    /// attacker must break both algorithms to forge a valid binary.
    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        let ed_sig = self.ed25519_signing.sign(message);
        let mldsa_sig = mldsa65::detached_sign(message, &self.mldsa_secret);
        HybridSignature {
            ed25519_sig: ed_sig.to_bytes().to_vec(),
            mldsa_sig: mldsa_sig.as_bytes().to_vec(),
        }
    }
}

/// Real, genuine hybrid verify -- requires BOTH signatures to be
/// valid. Classical OR quantum break alone is insufficient.
pub fn verify_hybrid(
    message: &[u8],
    sig: &HybridSignature,
    ed25519_pub: &Ed25519VerifyingKey,
    mldsa_pub: &mldsa65::PublicKey,
) -> bool {
    let ed_sig_bytes: [u8; 64] = match sig.ed25519_sig.as_slice().try_into() {
        Ok(b) => b,
        Err(_) => return false,
    };
    let ed_sig = Ed25519Signature::from_bytes(&ed_sig_bytes);
    let ed_ok = ed25519_pub.verify_strict(message, &ed_sig).is_ok();

    let mldsa_sig = match mldsa65::DetachedSignature::from_bytes(&sig.mldsa_sig) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mldsa_ok = mldsa65::verify_detached_signature(&mldsa_sig, message, mldsa_pub).is_ok();

    ed_ok && mldsa_ok
}
