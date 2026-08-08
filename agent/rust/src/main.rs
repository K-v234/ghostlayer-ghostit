//! Ghost IT Agent — Userspace Daemon
//! 
//! Reads kernel events from eBPF ring buffer,
//! normalizes them, and forwards to the telemetry pipeline.
//!
//! Ghost Layer Technologies — CONFIDENTIAL

mod hybrid_sign;
mod tls_pin;
use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod events;
mod pipeline;
mod protection;
mod updater;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .with_target(false)
        .with_thread_ids(false)
        .json()
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Ghost IT Agent starting"
    );

    // Load configuration
    let config = config::AgentConfig::load()?;
    info!(
        pipeline_host = %config.pipeline_host,
        pipeline_port = config.pipeline_port,
        "Configuration loaded"
    );

    // Start self-protection watchdog (C6)
    protection::start_watchdog(&config).await?;
    let own_binary_path = std::env::current_exe()
        .ok()
        .and_then(|p| p.to_str().map(String::from))
        .unwrap_or_else(|| "/home/ubuntu/ghostlayer/ghostit-agent-linux-amd64".to_string());
    updater::spawn_update_checker(config.pipeline_host.clone(), own_binary_path);

    // Start pipeline forwarder
    let pipeline = pipeline::PipelineForwarder::new(
        &config.pipeline_host,
        config.pipeline_port,
        config.batch_size,
        config.flush_interval_ms,
        config.customer_id.clone(),
        config.api_key.clone(),
    ).await?;

    // Start eBPF event loop (C1)
    info!("Starting eBPF event loop");
    events::run_event_loop(pipeline, &config).await?;

    info!("Ghost IT Agent stopped");
    Ok(())
}
