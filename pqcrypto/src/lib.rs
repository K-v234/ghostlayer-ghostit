// GhostIT C11 — Post-Quantum Communications
// Ghost Layer Technologies · Chennai · June 2026
pub mod kem;
pub mod hybrid;
pub mod grpc_interceptor;
pub use hybrid::{HybridKem, HybridSharedSecret};
pub use kem::{MlKem768, KemKeyPair};

// ── PyO3 Python bindings ──────────────────────────────────────────────────────
use pyo3::prelude::*;
use crate::hybrid::{HybridPublicKey, HybridSecretKey, HybridCiphertext};

fn err(e: impl std::fmt::Display) -> PyErr {
    pyo3::exceptions::PyRuntimeError::new_err(e.to_string())
}

/// Generate hybrid keypair.
/// Returns (x25519_pk_hex + mlkem_pk_hex, x25519_sk_hex + mlkem_sk_hex)
/// Public key = 32 + 1184 = 1216 bytes total
/// Secret key = 32 + 2400 = 2432 bytes total
#[pyfunction]
fn generate_keypair() -> PyResult<(String, String)> {
    let kem = HybridKem::new().map_err(err)?;
    let kp  = kem.generate_keypair().map_err(err)?;
    // Serialize public key: x25519(32) || mlkem(1184)
    let mut pub_bytes = kp.public_key.x25519_pk.clone();
    pub_bytes.extend_from_slice(&kp.public_key.mlkem_pk);
    // Serialize secret key: x25519_sk(32) || mlkem_sk
    let x25519_sk_bytes: [u8;32] = kp.secret_key.x25519_sk.to_bytes();
    let mut sk_bytes = x25519_sk_bytes.to_vec();
    sk_bytes.extend_from_slice(&kp.secret_key.mlkem_sk);
    Ok((hex::encode(pub_bytes), hex::encode(sk_bytes)))
}

/// Encapsulate — client/agent side.
/// Input: public_key_hex (1216 bytes = 32 x25519 + 1184 mlkem)
/// Returns: (ciphertext_hex, session_key_hex)
#[pyfunction]
fn encapsulate(public_key_hex: &str) -> PyResult<(String, String)> {
    let pub_bytes = hex::decode(public_key_hex).map_err(err)?;
    if pub_bytes.len() < 32 + 1184 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            format!("Public key too short: {} bytes", pub_bytes.len())
        ));
    }
    let pk = HybridPublicKey {
        x25519_pk: pub_bytes[..32].to_vec(),
        mlkem_pk:  pub_bytes[32..32+1184].to_vec(),
    };
    let kem = HybridKem::new().map_err(err)?;
    let (ct, ss) = kem.encapsulate(&pk).map_err(err)?;
    // Serialize ciphertext: x25519_eph(32) || mlkem_ct(1088)
    let mut ct_bytes = ct.x25519_ephemeral_pk.clone();
    ct_bytes.extend_from_slice(&ct.mlkem_ciphertext);
    Ok((hex::encode(ct_bytes), hex::encode(ss.key_bytes)))
}

/// Decapsulate — server side.
/// Input: secret_key_hex, ciphertext_hex
/// Returns: session_key_hex
#[pyfunction]
fn decapsulate(secret_key_hex: &str, ciphertext_hex: &str) -> PyResult<String> {
    let sk_bytes = hex::decode(secret_key_hex).map_err(err)?;
    let ct_bytes = hex::decode(ciphertext_hex).map_err(err)?;
    if sk_bytes.len() < 32 { return Err(pyo3::exceptions::PyValueError::new_err("SK too short")); }
    if ct_bytes.len() < 32 + 1088 { return Err(pyo3::exceptions::PyValueError::new_err("CT too short")); }

    // Reconstruct secret key
    let mut x25519_arr = [0u8; 32];
    x25519_arr.copy_from_slice(&sk_bytes[..32]);
    let sk = HybridSecretKey {
        x25519_sk: x25519_dalek::StaticSecret::from(x25519_arr),
        mlkem_sk:  sk_bytes[32..].to_vec(),
    };
    // Reconstruct ciphertext
    let ct = HybridCiphertext {
        x25519_ephemeral_pk: ct_bytes[..32].to_vec(),
        mlkem_ciphertext:    ct_bytes[32..32+1088].to_vec(),
    };
    let kem = HybridKem::new().map_err(err)?;
    let ss  = kem.decapsulate(&sk, &ct).map_err(err)?;
    Ok(hex::encode(ss.key_bytes))
}

#[pymodule]
fn pqcrypto(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(decapsulate, m)?)?;
    m.add("__version__", "0.1.0")?;
    Ok(())
}
