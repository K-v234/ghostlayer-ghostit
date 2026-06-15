//! Ghost IT Agent — Userspace Daemon
//! 
//! Reads kernel events from eBPF ring buffer,
//! normalizes them, and forwards to the telemetry pipeline.
//!
//! Ghost Layer Technologies — CONFIDENTIAL

use anyhow::Result;
use tracing::info;
use tracing_subscriber::EnvFilter;

mod config;
mod events;
mod pipeline;
mod protection;

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

    // Start pipeline forwarder
    let pipeline = pipeline::PipelineForwarder::new(
        &config.pipeline_host,
        config.pipeline_port,
        config.batch_size,
        config.flush_interval_ms,
    ).await?;

    // Start eBPF event loop (C1)
    info!("Starting eBPF event loop");
    events::run_event_loop(pipeline, &config).await?;

    info!("Ghost IT Agent stopped");
    Ok(())
}
