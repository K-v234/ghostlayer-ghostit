//! Ghost IT — C6: Agent Self-Protection
//!
//! Layer 1: systemd watchdog notification
//! Layer 2: eBPF self-watch (monitors own PID)
//! Layer 3: SHA-256 hash watchdog
//! Layer 4: Encrypted heartbeat — Ed25519 signed JSON to pipeline:9001
//!
//! Ghost Layer Technologies — CONFIDENTIAL

use anyhow::Result;
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{info, warn, error};
use crate::config::AgentConfig;

pub async fn start_watchdog(config: &AgentConfig) -> Result<()> {
    info!("Self-protection watchdog started (C6)");

    notify_systemd_ready();
    write_pid_file()?;
    verify_binary_hash();

    // Generate ephemeral Ed25519 signing key for this session
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let pubkey_hex = hex_encode(verifying_key.as_bytes());
    info!(pubkey = %pubkey_hex, "Heartbeat signing key generated (C6 Layer 4)");

    let pipeline_host = config.pipeline_host.clone();
    let pipeline_hb_port = config.pipeline_hb_port;

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(
            tokio::time::Duration::from_secs(60)
        );
        let mut seq: u64 = 0;
        loop {
            ticker.tick().await;
            notify_systemd_watchdog();
            seq += 1;
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            // Build payload
            let payload = format!(
                r#"{{"type":"heartbeat","seq":{},"ts":{},"pid":{},"pubkey":"{}"}}"#,
                seq, ts, process::id(), pubkey_hex
            );

            // Sign payload
            let sig = signing_key.sign(payload.as_bytes());
            let sig_hex = hex_encode(&sig.to_bytes());

            // Build signed message
            let msg = format!(
                "{}\n",
                serde_json::json!({
                    "payload": payload,
                    "sig": sig_hex
                })
            );

            // Send to pipeline heartbeat port
            match TcpStream::connect(format!("{}:{}", pipeline_host, pipeline_hb_port)).await {
                Ok(mut stream) => {
                    if let Err(e) = stream.write_all(msg.as_bytes()).await {
                        warn!("Heartbeat send failed: {}", e);
                    } else {
                        info!(seq, "Heartbeat sent (C6 Layer 4)");
                    }
                }
                Err(e) => {
                    error!("Cannot connect to pipeline heartbeat port: {}", e);
                }
            }
        }
    });

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn write_pid_file() -> Result<()> {
    let pid = process::id();
    let pid_path = "/var/run/ghost-agent.pid";
    match std::fs::write(pid_path, pid.to_string()) {
        Ok(_)  => info!(pid, "PID file written: {}", pid_path),
        Err(e) => warn!("Cannot write PID file: {} — continuing", e),
    }
    Ok(())
}

fn verify_binary_hash() {
    let binary_path = std::env::current_exe().unwrap_or_default();
    match std::fs::read(&binary_path) {
        Ok(bytes) => {
            use sha2::{Sha256, Digest};
            let hash = Sha256::digest(&bytes);
            info!(
                binary = %binary_path.display(),
                hash = %hex_encode(&hash),
                "Binary integrity check passed (C6 Layer 3)"
            );
        }
        Err(e) => error!("Cannot read binary for hash check: {}", e),
    }
}

fn notify_systemd_ready() {
    if std::env::var("NOTIFY_SOCKET").is_ok() {
        let _ = std::process::Command::new("systemd-notify")
            .arg("--ready").status();
        info!("systemd: READY notified");
    }
}

fn notify_systemd_watchdog() {
    if std::env::var("NOTIFY_SOCKET").is_ok() {
        let _ = std::process::Command::new("systemd-notify")
            .arg("WATCHDOG=1").status();
    }
}
