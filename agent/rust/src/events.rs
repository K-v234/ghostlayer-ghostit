//! Ghost IT C1 — eBPF Ring Buffer Reader
//!
//! Loads ghost_agent.bpf.o, attaches all 47 programs,
//! reads directly from dual priority ring buffers,
//! forwards normalized events to pipeline.
//!
//! Replaces: ghost_agent C binary + Python forwarder
//! Ghost Layer Technologies — CONFIDENTIAL

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, info, error};
use crate::config::AgentConfig;
use crate::pipeline::PipelineForwarder;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder, MapCore};
use std::mem;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// ------------------------------------------------------------------ //
// Event types — mirrors kernel ghost_agent.h                          //
// ------------------------------------------------------------------ //

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventType {
    Exec = 1, Open = 2, Connect = 3, Clone = 4, Unlink = 5,
    Setuid = 6, Setgid = 7, Ptrace = 8, Capset = 9,
    MmapExec = 10, Mprotect = 11, Bind = 12, Listen = 13,
    Accept = 14, Sendto = 15, Openat2 = 16, Rename = 17,
    Chmod = 18, Chown = 19, Exit = 20, Prctl = 21,
    Fork = 22, Vfork = 23, Read = 24, Write = 25,
    Sendmsg = 26, Recvfrom = 27, Recvmsg = 28,
    Setreuid = 29, Setregid = 30, Setns = 31,
    EntropyRead = 32, CapCheck = 33, LsmOpen = 34,
    Socket = 35, Accept4 = 36, Dup2 = 37, Dup3 = 38,
    Kill = 39, Tgkill = 40, TcpConnect = 41, TcpAccept = 42,
    TcpClose = 43, UdpSend = 44, UdpRecv = 45,
    InodePerm = 46, PerfOpen = 47,
    Unknown = 0,
}

impl EventType {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Exec, 2 => Self::Open, 3 => Self::Connect,
            4 => Self::Clone, 5 => Self::Unlink, 6 => Self::Setuid,
            7 => Self::Setgid, 8 => Self::Ptrace, 9 => Self::Capset,
            10 => Self::MmapExec, 11 => Self::Mprotect, 12 => Self::Bind,
            13 => Self::Listen, 14 => Self::Accept, 15 => Self::Sendto,
            16 => Self::Openat2, 17 => Self::Rename, 18 => Self::Chmod,
            19 => Self::Chown, 20 => Self::Exit, 21 => Self::Prctl,
            22 => Self::Fork, 23 => Self::Vfork, 24 => Self::Read,
            25 => Self::Write, 26 => Self::Sendmsg, 27 => Self::Recvfrom,
            28 => Self::Recvmsg, 29 => Self::Setreuid, 30 => Self::Setregid,
            31 => Self::Setns, 32 => Self::EntropyRead, 33 => Self::CapCheck,
            34 => Self::LsmOpen, 35 => Self::Socket, 36 => Self::Accept4,
            37 => Self::Dup2, 38 => Self::Dup3, 39 => Self::Kill,
            40 => Self::Tgkill, 41 => Self::TcpConnect, 42 => Self::TcpAccept,
            43 => Self::TcpClose, 44 => Self::UdpSend, 45 => Self::UdpRecv,
            46 => Self::InodePerm, 47 => Self::PerfOpen,
            _ => Self::Unknown,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Exec => "exec", Self::Open => "open",
            Self::Connect => "connect", Self::Clone => "clone",
            Self::Unlink => "unlink", Self::Setuid => "setuid",
            Self::Setgid => "setgid", Self::Ptrace => "ptrace",
            Self::Capset => "capset", Self::MmapExec => "mmap_exec",
            Self::Mprotect => "mprotect", Self::Bind => "bind",
            Self::Listen => "listen", Self::Accept => "accept",
            Self::Sendto => "sendto", Self::Openat2 => "openat2",
            Self::Rename => "rename", Self::Chmod => "chmod",
            Self::Chown => "chown", Self::Exit => "exit",
            Self::Prctl => "prctl", Self::Fork => "fork",
            Self::Vfork => "vfork", Self::Read => "read",
            Self::Write => "write", Self::Sendmsg => "sendmsg",
            Self::Recvfrom => "recvfrom", Self::Recvmsg => "recvmsg",
            Self::Setreuid => "setreuid", Self::Setregid => "setregid",
            Self::Setns => "setns", Self::EntropyRead => "entropy_read",
            Self::CapCheck => "cap_check", Self::LsmOpen => "lsm_open",
            Self::Socket => "socket", Self::Accept4 => "accept4",
            Self::Dup2 => "dup2", Self::Dup3 => "dup3",
            Self::Kill => "kill", Self::Tgkill => "tgkill",
            Self::TcpConnect => "tcp_connect", Self::TcpAccept => "tcp_accept",
            Self::TcpClose => "tcp_close", Self::UdpSend => "udp_send",
            Self::UdpRecv => "udp_recv", Self::InodePerm => "inode_perm",
            Self::PerfOpen => "perf_open", Self::Unknown => "unknown",
        }
    }
}

// ------------------------------------------------------------------ //
// Raw event struct — must match kernel ghost_event exactly (128 bytes)//
// ------------------------------------------------------------------ //

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RawGhostEvent {
    pub timestamp_ns: u64,   // 8
    pub pid:          u32,   // 4
    pub tgid:         u32,   // 4
    pub uid:          u32,   // 4
    pub gid:          u32,   // 4
    pub parent_pid:   u64,   // 8
    pub event_type:   u8,    // 1
    pub priority:     u8,    // 1
    pub flags:        u16,   // 2
    pub comm:         [u8; 16], // 16
    pub path:         [u8; 64], // 64
    pub _pad:         [u8; 12], // 12  → total = 128
}

const RAW_EVENT_SIZE: usize = 128; // kernel ghost_event is 128 bytes packed

/// Normalized event for pipeline
#[derive(Debug, Clone, Serialize)]
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
    pub score:      u8,
}

impl GhostEvent {
    fn from_raw(raw: &RawGhostEvent) -> Option<Self> {
        let comm = std::str::from_utf8(&raw.comm)
            .unwrap_or("").trim_end_matches('\0').to_string();
        let path_str = std::str::from_utf8(&raw.path)
            .unwrap_or("").trim_end_matches('\0').to_string();
        let et = EventType::from_u8(raw.event_type);

        // Suspicion score: critical ring = 60 base, standard = 10
        let score = if raw.priority == 1 { 60 } else { 10 };

        Some(GhostEvent {
            ts:         raw.timestamp_ns,
            pid:        raw.pid,
            ppid:       raw.parent_pid,
            uid:        raw.uid,
            gid:        raw.gid,
            comm,
            event_type: et.as_str().to_string(),
            priority:   raw.priority,
            path:       if path_str.is_empty() { None } else { Some(path_str) },
            flags:      raw.flags,
            score,
        })
    }
}

// ------------------------------------------------------------------ //
// BPF object path                                                      //
// ------------------------------------------------------------------ //

fn bpf_obj_path() -> String {
    std::env::var("GHOST_BPF_OBJ")
        .unwrap_or_else(|_| {
            dirs_home().map(|h| format!("{}/ghostlayer/agent/ebpf/ghost_agent.bpf.o", h))
                .unwrap_or_else(|| "/home/keerthivahanan/ghostlayer/agent/ebpf/ghost_agent.bpf.o".to_string())
        })
}

fn dirs_home() -> Option<String> {
    std::env::var("HOME").ok()
}

// ------------------------------------------------------------------ //
// Main event loop                                                      //
// ------------------------------------------------------------------ //

pub async fn run_event_loop(
    pipeline: PipelineForwarder,
    config: &AgentConfig,
) -> Result<()> {
    let bpf_path = bpf_obj_path();
    info!(path = %bpf_path, "Loading BPF object");

    // Shared pipeline behind Arc<Mutex> for ring buffer callbacks
    let pipeline = Arc::new(Mutex::new(pipeline));
    let counter  = Arc::new(Mutex::new(0u64));

    // Open + load BPF object
    let mut builder = ObjectBuilder::default();
    let mut obj = builder
        .open_file(&bpf_path)
        .with_context(|| format!("Cannot open BPF object: {}", bpf_path))?
        .load()
        .context("Cannot load BPF object")?;

    // Auto-attach all programs
    let mut links = Vec::new();
    let mut attached = 0usize;
    for prog in obj.progs_mut() {
        match prog.attach() {
            Ok(link) => {
                info!("Attached: {}", prog.name().to_string_lossy());
                links.push(link);
                attached += 1;
            }
            Err(e) => {
                warn!("Could not attach {}: {}", prog.name().to_string_lossy(), e);
            }
        }
    }
    info!(attached, "BPF programs attached");

    // Build ring buffer reader
    let p1 = Arc::clone(&pipeline);
    let c1 = Arc::clone(&counter);
    let p2 = Arc::clone(&pipeline);
    let c2 = Arc::clone(&counter);

    let mut rb_builder = RingBufferBuilder::new();

    // Critical ring buffer
    // Collect all maps first — must outlive rb_builder and rb
    let all_maps: Vec<_> = obj.maps().collect();

    for map in &all_maps {
        let name = map.name().to_string_lossy().to_string();
        if name == "critical_rb" {
            let p = Arc::clone(&p1);
            let c = Arc::clone(&c1);
            rb_builder.add(map, move |data: &[u8]| {
                handle_event(data, &p, &c, true);
                0
            }).context("Failed to add critical_rb")?;
            info!("Subscribed to critical_rb");
        } else if name == "standard_rb" {
            let p = Arc::clone(&p2);
            let c = Arc::clone(&c2);
            rb_builder.add(map, move |data: &[u8]| {
                handle_event(data, &p, &c, false);
                0
            }).context("Failed to add standard_rb")?;
            info!("Subscribed to standard_rb");
        }
    }

    let rb = rb_builder.build().context("Failed to build ring buffer")?;
    info!("Ring buffer reader ready — polling for events");

    // Poll loop — runs forever
    loop {
        match rb.poll(Duration::from_millis(100)) {
            Ok(_) => {}
            Err(e) => {
                error!("Ring buffer poll error: {}", e);
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

fn handle_event(
    data: &[u8],
    pipeline: &Arc<Mutex<PipelineForwarder>>,
    counter: &Arc<Mutex<u64>>,
    _critical: bool,
) {
    if data.len() < RAW_EVENT_SIZE {
        warn!("Short event: {} bytes (expected {})", data.len(), RAW_EVENT_SIZE);
        return;
    }

    // Safety: data is kernel-written, size-checked above
    let raw = unsafe { &*(data.as_ptr() as *const RawGhostEvent) };

    if let Some(event) = GhostEvent::from_raw(raw) {
        let json = match serde_json::to_value(&event) {
            Ok(v) => v,
            Err(e) => { warn!("Serialize error: {}", e); return; }
        };

        // Forward to pipeline (blocking lock — acceptable in callback context)
        if let Ok(mut p) = pipeline.try_lock() {
            // Use tokio block_in_place for async forward
            let rt = tokio::runtime::Handle::try_current();
            if let Ok(handle) = rt {
                handle.block_on(async {
                    if let Err(e) = p.forward(json).await {
                        warn!("Forward error: {}", e);
                    }
                });
            }
        }

        if let Ok(mut c) = counter.try_lock() {
            *c += 1;
            if *c % 1000 == 0 {
                debug!(count = *c, "Events processed");
            }
        }
    }
}
