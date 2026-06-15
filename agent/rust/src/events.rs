//! eBPF event definitions and ring buffer reader

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use crate::config::AgentConfig;
use crate::pipeline::PipelineForwarder;

/// Event types matching kernel eBPF program
#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EventType {
    Exec    = 1,
    Open    = 2,
    Connect = 3,
    Clone   = 4,
    Unlink  = 5,
    // V0.2 additions
    Setuid  = 6,
    Mmap    = 7,
    Ptrace  = 8,
}

impl EventType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Exec),
            2 => Some(Self::Open),
            3 => Some(Self::Connect),
            4 => Some(Self::Clone),
            5 => Some(Self::Unlink),
            6 => Some(Self::Setuid),
            7 => Some(Self::Mmap),
            8 => Some(Self::Ptrace),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Exec    => "exec",
            Self::Open    => "open",
            Self::Connect => "connect",
            Self::Clone   => "clone",
            Self::Unlink  => "unlink",
            Self::Setuid  => "setuid",
            Self::Mmap    => "mmap",
            Self::Ptrace  => "ptrace",
        }
    }
}

/// Priority level — matches kernel ring buffer selection
#[repr(u8)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Priority {
    Standard = 0,
    Critical = 1,
}

/// Core event struct — mirrors kernel ghost_event (128 bytes)
#[repr(C, packed)]
#[derive(Debug, Clone)]
pub struct RawGhostEvent {
    pub timestamp_ns: u64,
    pub pid:          u32,
    pub tgid:         u32,
    pub uid:          u32,
    pub gid:          u32,
    pub parent_pid:   u64,
    pub event_type:   u8,
    pub priority:     u8,
    pub flags:        u16,
    pub comm:         [u8; 16],
    pub path:         [u8; 64],
    pub _pad:         [u8; 16],
}

/// Normalized event for pipeline forwarding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostEvent {
    pub ts:         u64,
    pub pid:        u32,
    pub ppid:       u64,
    pub uid:        u32,
    pub gid:        u32,
    pub comm:       String,
    pub event_type: String,
    pub priority:   u8,
    pub path:       Option<String>,
    pub flags:      u16,
}

impl GhostEvent {
    pub fn from_raw(raw: &RawGhostEvent) -> Option<Self> {
        let comm = std::str::from_utf8(&raw.comm)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let path_str = std::str::from_utf8(&raw.path)
            .unwrap_or("")
            .trim_end_matches('\0')
            .to_string();

        let event_type = EventType::from_u8(raw.event_type)?;

        Some(GhostEvent {
            ts:         raw.timestamp_ns,
            pid:        raw.pid,
            ppid:       raw.parent_pid,
            uid:        raw.uid,
            gid:        raw.gid,
            comm,
            event_type: event_type.as_str().to_string(),
            priority:   raw.priority,
            path:       if path_str.is_empty() { None } else { Some(path_str) },
            flags:      raw.flags,
        })
    }
}

/// Main eBPF event loop
/// Reads from ring buffer and forwards to pipeline
pub async fn run_event_loop(
    mut pipeline: PipelineForwarder,
    _config: &AgentConfig,
) -> Result<()> {
    // TODO: Initialize libbpf-rs skel and attach programs
    // For now: read from stdin (compatibility with existing eBPF C agent)
    use tokio::io::{AsyncBufReadExt, BufReader};

    let stdin = tokio::io::stdin();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    let mut count = 0u64;

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        match serde_json::from_str::<serde_json::Value>(&line) {
            Ok(event) => {
                pipeline.forward(event).await?;
                count += 1;
                if count % 1000 == 0 {
                    debug!(count, "Events processed");
                }
            }
            Err(e) => {
                warn!(error = %e, raw = %&line[..line.len().min(80)], "Bad event");
            }
        }
    }

    pipeline.flush().await?;
    Ok(())
}
