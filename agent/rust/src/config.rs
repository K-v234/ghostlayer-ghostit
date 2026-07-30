//! Agent configuration

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct AgentConfig {
    /// Pipeline server host
    pub pipeline_host: String,

    /// Pipeline server TCP port
    pub pipeline_port: u16,

    /// Minimum UID to monitor (filter out kernel threads)
    pub min_uid: u32,

    /// Batch size before flush
    pub batch_size: usize,

    /// Maximum ms between flushes
    pub flush_interval_ms: u64,

    /// Heartbeat port (C6 Layer 4)
    pub pipeline_hb_port: u16,
    /// Log level
    pub log_level: String,
    pub customer_id: String,
    pub api_key: String,
}

impl AgentConfig {
    pub fn load() -> Result<Self> {
        // Defaults — override via environment variables
        Ok(Self {
            pipeline_host: std::env::var("GHOST_PIPELINE_HOST")
                .unwrap_or_else(|_| "127.0.0.1".to_string()),
            pipeline_port: std::env::var("GHOST_PIPELINE_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9000),
            min_uid: std::env::var("GHOST_MIN_UID")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),
            batch_size: std::env::var("GHOST_BATCH_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(50),
            flush_interval_ms: std::env::var("GHOST_FLUSH_INTERVAL_MS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(5000),
            pipeline_hb_port: std::env::var("GHOST_HB_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9001),
            log_level: std::env::var("GHOST_LOG_LEVEL")
                .unwrap_or_else(|_| "info".to_string()),
            customer_id: std::env::var("GHOST_CUSTOMER_ID")
                .unwrap_or_else(|_| "unassigned".to_string()),
            api_key: std::env::var("GHOST_API_KEY")
                .unwrap_or_else(|_| "".to_string()),
        })
    }
}
