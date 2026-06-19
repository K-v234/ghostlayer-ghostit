//! Ghost IT C1 — eBPF Ring Buffer Reader
//! Loads BPF, attaches 47 programs, reads ring buffers,
//! forwards events to pipeline via channel.

use anyhow::{Result, Context};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn, info, error};
use crate::config::AgentConfig;
use crate::pipeline::PipelineForwarder;
use libbpf_rs::{ObjectBuilder, RingBufferBuilder, MapCore};
use std::mem;
use std::sync::mpsc;
use std::time::Duration;

// Event types
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventType {
    Unknown = 0,
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
}

impl EventType {
    fn from_u8(v: u8) -> Self {
        match v {
            1=>Self::Exec, 2=>Self::Open, 3=>Self::Connect,
            4=>Self::Clone, 5=>Self::Unlink, 6=>Self::Setuid,
            7=>Self::Setgid, 8=>Self::Ptrace, 9=>Self::Capset,
            10=>Self::MmapExec, 11=>Self::Mprotect, 12=>Self::Bind,
            13=>Self::Listen, 14=>Self::Accept, 15=>Self::Sendto,
            16=>Self::Openat2, 17=>Self::Rename, 18=>Self::Chmod,
            19=>Self::Chown, 20=>Self::Exit, 21=>Self::Prctl,
            22=>Self::Fork, 23=>Self::Vfork, 24=>Self::Read,
            25=>Self::Write, 26=>Self::Sendmsg, 27=>Self::Recvfrom,
            28=>Self::Recvmsg, 29=>Self::Setreuid, 30=>Self::Setregid,
            31=>Self::Setns, 32=>Self::EntropyRead, 33=>Self::CapCheck,
            34=>Self::LsmOpen, 35=>Self::Socket, 36=>Self::Accept4,
            37=>Self::Dup2, 38=>Self::Dup3, 39=>Self::Kill,
            40=>Self::Tgkill, 41=>Self::TcpConnect, 42=>Self::TcpAccept,
            43=>Self::TcpClose, 44=>Self::UdpSend, 45=>Self::UdpRecv,
            46=>Self::InodePerm, 47=>Self::PerfOpen,
            _ => Self::Unknown,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Exec=>"exec", Self::Open=>"open", Self::Connect=>"connect",
            Self::Clone=>"clone", Self::Unlink=>"unlink", Self::Setuid=>"setuid",
            Self::Setgid=>"setgid", Self::Ptrace=>"ptrace", Self::Capset=>"capset",
            Self::MmapExec=>"mmap_exec", Self::Mprotect=>"mprotect",
            Self::Bind=>"bind", Self::Listen=>"listen", Self::Accept=>"accept",
            Self::Sendto=>"sendto", Self::Openat2=>"openat2", Self::Rename=>"rename",
            Self::Chmod=>"chmod", Self::Chown=>"chown", Self::Exit=>"exit",
            Self::Prctl=>"prctl", Self::Fork=>"fork", Self::Vfork=>"vfork",
            Self::Read=>"read", Self::Write=>"write", Self::Sendmsg=>"sendmsg",
            Self::Recvfrom=>"recvfrom", Self::Recvmsg=>"recvmsg",
            Self::Setreuid=>"setreuid", Self::Setregid=>"setregid",
            Self::Setns=>"setns", Self::EntropyRead=>"entropy_read",
            Self::CapCheck=>"cap_check", Self::LsmOpen=>"lsm_open",
            Self::Socket=>"socket", Self::Accept4=>"accept4",
            Self::Dup2=>"dup2", Self::Dup3=>"dup3", Self::Kill=>"kill",
            Self::Tgkill=>"tgkill", Self::TcpConnect=>"tcp_connect",
            Self::TcpAccept=>"tcp_accept", Self::TcpClose=>"tcp_close",
            Self::UdpSend=>"udp_send", Self::UdpRecv=>"udp_recv",
            Self::InodePerm=>"inode_perm", Self::PerfOpen=>"perf_open",
            Self::Unknown=>"unknown",
        }
    }
}

// Kernel event struct — must match ghost_agent.h exactly (128 bytes packed)
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
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
    pub _pad:         [u8; 12],
}

const RAW_EVENT_SIZE: usize = 128;

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
        let score = if raw.priority == 1 { 60 } else { 10 };
        Some(GhostEvent {
            ts: raw.timestamp_ns, pid: raw.pid, ppid: raw.parent_pid,
            uid: raw.uid, gid: raw.gid, comm,
            event_type: et.as_str().to_string(),
            priority: raw.priority,
            path: if path_str.is_empty() { None } else { Some(path_str) },
            flags: raw.flags, score,
        })
    }
}

fn bpf_obj_path() -> String {
    std::env::var("GHOST_BPF_OBJ").unwrap_or_else(|_|
        format!("{}/ghostlayer/agent/ebpf/ghost_agent.bpf.o",
            std::env::var("HOME").unwrap_or_else(|_| "/home/keerthivahanan".to_string()))
    )
}

pub async fn run_event_loop(
    mut pipeline: PipelineForwarder,
    _config: &AgentConfig,
) -> Result<()> {
    let bpf_path = bpf_obj_path();
    info!(path = %bpf_path, "Loading BPF object");

    // std channel: ring buffer thread -> async task
    let (tx, rx) = mpsc::sync_channel::<serde_json::Value>(10000); // bounded — drop events if full

    // Spawn std thread for BPF polling (not async — avoids runtime conflict)
    let tx_clone = tx.clone();
    std::thread::spawn(move || {
        let mut builder = ObjectBuilder::default();
        let mut obj = match builder.open_file(&bpf_path) {
            Ok(o) => match o.load() {
                Ok(loaded) => loaded,
                Err(e) => { error!("BPF load failed: {}", e); return; }
            },
            Err(e) => { error!("BPF open failed: {}", e); return; }
        };

        // Attach all programs
        let mut attached = 0usize;
        let mut links = Vec::new();
        for prog in obj.progs_mut() {
            match prog.attach() {
                Ok(link) => { links.push(link); attached += 1; }
                Err(e) => warn!("Cannot attach {}: {}", prog.name().to_string_lossy(), e),
            }
        }
        info!(attached, "BPF programs attached");

        // Build ring buffer
        let all_maps: Vec<_> = obj.maps().collect();
        let mut rb_builder = RingBufferBuilder::new();

        for map in &all_maps {
            let name = map.name().to_string_lossy().to_string();
            if name == "critical_rb" || name == "standard_rb" {
                let t = tx_clone.clone();
                if let Err(e) = rb_builder.add(map, move |data: &[u8]| {
                    if data.len() >= RAW_EVENT_SIZE {
                        let raw = unsafe { &*(data.as_ptr() as *const RawGhostEvent) };
                        if let Some(event) = GhostEvent::from_raw(raw) {
                            if let Ok(json) = serde_json::to_value(&event) {
                                let _ = t.try_send(json); // drop event if channel full — prevents memory explosion
                            }
                        }
                    }
                    0
                }) {
                    warn!("Failed to add {}: {}", name, e);
                } else {
                    info!("Subscribed to {}", name);
                }
            }
        }

        let rb = match rb_builder.build() {
            Ok(r) => r,
            Err(e) => { error!("Ring buffer build failed: {}", e); return; }
        };

        info!("Ring buffer polling started");
        loop {
            if let Err(e) = rb.poll(Duration::from_millis(100)) {
                error!("Poll error: {}", e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    });

    // Async task: drain channel and forward to pipeline
    info!("Event forwarder ready");
    let mut count = 0u64;

    loop {
        // Drain all available events
        loop {
            match rx.try_recv() {
                Ok(event) => {
                    pipeline.forward(event).await?;
                    count += 1;
                    if count % 1000 == 0 {
                        debug!(count, "Events forwarded");
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    error!("BPF thread disconnected");
                    return Ok(());
                }
            }
        }
        // Yield to tokio runtime briefly
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}
