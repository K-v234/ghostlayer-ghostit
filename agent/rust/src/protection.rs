//! Agent self-protection (C6)
//! Layer 1: systemd watchdog notification
//! Layer 4: encrypted heartbeat placeholder

use anyhow::Result;
use tracing::info;
use crate::config::AgentConfig;

pub async fn start_watchdog(config: &AgentConfig) -> Result<()> {
    info!("Self-protection watchdog started");

    // Notify systemd we're ready (Layer 1)
    notify_systemd_ready();

    // Start heartbeat loop (Layer 4 — placeholder for V0)
    let _ = config;
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(
            tokio::time::Duration::from_secs(30)
        );
        loop {
            ticker.tick().await;
            // Notify systemd watchdog
            notify_systemd_watchdog();
        }
    });

    Ok(())
}

fn notify_systemd_ready() {
    // sd_notify(READY=1)
    if let Ok(_) = std::env::var("NOTIFY_SOCKET") {
        let _ = std::process::Command::new("systemd-notify")
            .arg("--ready")
            .status();
    }
}

fn notify_systemd_watchdog() {
    if let Ok(_) = std::env::var("NOTIFY_SOCKET") {
        let _ = std::process::Command::new("systemd-notify")
            .arg("WATCHDOG=1")
            .status();
    }
}
