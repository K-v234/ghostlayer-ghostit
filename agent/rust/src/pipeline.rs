//! Pipeline forwarder — sends events to Ghost IT pipeline via TCP

use anyhow::Result;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time::{interval, timeout, Duration};
use tracing::{info, warn, error, debug};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::path::PathBuf;
use tokio::fs::{OpenOptions, File};
use tokio::io::AsyncReadExt;
use tokio_rustls::client::TlsStream;

struct DurableOutbox {
    path: PathBuf,
}
impl DurableOutbox {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }
    async fn append(&self, payload: &str) -> Result<()> {
        let mut f = OpenOptions::new()
            .create(true).append(true).open(&self.path).await?;
        f.write_all(payload.as_bytes()).await?;
        Ok(())
    }
    async fn read_all(&self) -> Result<String> {
        if !self.path.exists() {
            return Ok(String::new());
        }
        let mut f = File::open(&self.path).await?;
        let mut buf = String::new();
        f.read_to_string(&mut buf).await?;
        Ok(buf)
    }
    async fn clear(&self) -> Result<()> {
        if self.path.exists() {
            tokio::fs::remove_file(&self.path).await?;
        }
        Ok(())
    }
    fn pending_bytes(&self) -> u64 {
        std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }
}

pub struct PipelineForwarder {
    host:             String,
    port:             u16,
    batch_size:       usize,
    flush_interval_ms: u64,
    batch:            Arc<Mutex<Vec<Value>>>,
    stream:           Arc<Mutex<Option<TlsStream<TcpStream>>>>,
    outbox:           Arc<DurableOutbox>,
    customer_id:      String,
    api_key:          String,
}

impl PipelineForwarder {
    pub async fn new(
        host: &str,
        port: u16,
        batch_size: usize,
        flush_interval_ms: u64,
        customer_id: String,
        api_key: String,
    ) -> Result<Self> {
        let outbox_path = std::env::var("GHOST_OUTBOX_PATH")
            .unwrap_or_else(|_| "/var/lib/ghostit/outbox.jsonl".to_string());
        let outbox = Arc::new(DurableOutbox::new(PathBuf::from(outbox_path)));
        let forwarder = Self {
            host:             host.to_string(),
            port,
            batch_size,
            flush_interval_ms,
            batch:            Arc::new(Mutex::new(Vec::new())),
            stream:           Arc::new(Mutex::new(None)),
            outbox,
            customer_id,
            api_key,
        };

        forwarder.connect().await;
        let pending = forwarder.outbox.pending_bytes();
        if pending > 0 {
            warn!(bytes = pending, "Durable outbox has pending undelivered data from a previous session -- will retry on next flush");
        }
        forwarder.start_timer();
        Ok(forwarder)
    }

    async fn connect(&self) {
        match crate::tls_pin::connect(&self.host, self.port).await {
            Ok(mut s) => {
                let auth_line = format!("{}\n", self.api_key);
                if let Err(e) = s.write_all(auth_line.as_bytes()).await {
                    warn!(error = %e, "Failed to send API key -- connection unusable");
                    return;
                }
                info!(host = %self.host, port = self.port, "Connected to pipeline");
                *self.stream.lock().await = Some(s);
            }
            Err(e) => {
                warn!(error = %e, "Pipeline unavailable — stdout fallback");
            }
        }
    }

    fn start_timer(&self) {
        let batch  = Arc::clone(&self.batch);
        let stream = Arc::clone(&self.stream);
        let host   = self.host.clone();
        let port   = self.port;
        let ms     = self.flush_interval_ms;
        let outbox = Arc::clone(&self.outbox);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(ms));
            let mut tick_count: u64 = 0;
            loop {
                ticker.tick().await;
                tick_count += 1;
                if tick_count % 60 == 0 {
                    let mut s = stream.lock().await;
                    if s.is_some() {
                        info!("Periodic forced reconnect -- ensuring pipeline connection is genuinely fresh");
                        *s = None;
                    }
                    drop(s);
                }

                {
                    let mut b = batch.lock().await;
                    if !b.is_empty() {
                        let payload = format!("{}\n", serde_json::to_string(&*b).unwrap_or_default());
                        b.clear();
                        drop(b);
                        if let Err(e) = outbox.append(&payload).await {
                            error!(error = %e, "Failed to write to durable outbox -- this batch may be lost");
                        }
                    }
                }

                let pending = match outbox.read_all().await {
                    Ok(p) if !p.is_empty() => p,
                    _ => continue,
                };

                let mut s = stream.lock().await;
                let send_ok = if let Some(ref mut conn) = *s {
                    match timeout(Duration::from_secs(30), conn.write_all(pending.as_bytes())).await {
                        Ok(Ok(())) => true,
                        Ok(Err(e)) => {
                            warn!(error = %e, "Pipeline write failed -- reconnecting, data remains safely queued in durable outbox");
                            *s = None;
                            false
                        }
                        Err(_) => {
                            warn!(bytes = pending.len(), "Pipeline write timed out after 30s -- reconnecting, data remains safely queued in durable outbox");
                            *s = None;
                            false
                        }
                    }
                } else {
                    match timeout(Duration::from_secs(10), crate::tls_pin::connect(&host, port)).await {
                        Ok(Ok(mut conn)) => {
                            info!("Pipeline reconnected");
                            match conn.write_all(pending.as_bytes()).await {
                                Ok(()) => { *s = Some(conn); true }
                                Err(e) => {
                                    warn!(error = %e, "Pipeline reconnected but write failed -- data remains safely queued in durable outbox");
                                    false
                                }
                            }
                        }
                        Ok(Err(e)) => {
                            warn!(error = %e, "Pipeline reconnect failed -- data remains safely queued in durable outbox");
                            false
                        }
                        Err(_) => {
                            warn!("Pipeline reconnect timed out after 10s -- data remains safely queued in durable outbox");
                            false
                        }
                    }
                };
                drop(s);

                if send_ok {
                    if let Err(e) = outbox.clear().await {
                        error!(error = %e, "Failed to clear durable outbox after successful send");
                    }
                }
            }
        });
    }

    pub async fn forward(&mut self, mut event: Value) -> Result<()> {
        if let Value::Object(ref mut map) = event {
            map.insert("customer_id".to_string(), Value::String(self.customer_id.clone()));
        }
        let mut batch = self.batch.lock().await;
        batch.push(event);
        if batch.len() >= self.batch_size {
            let payload = format!("{}\n", serde_json::to_string(&*batch)?);
            batch.clear();
            drop(batch);
            self.send_payload(&payload).await;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        let mut batch = self.batch.lock().await;
        if batch.is_empty() {
            return Ok(());
        }
        let payload = format!("{}\n", serde_json::to_string(&*batch)?);
        batch.clear();
        drop(batch);
        self.send_payload(&payload).await;
        Ok(())
    }

    async fn send_payload(&self, payload: &str) {
        if let Err(e) = self.outbox.append(payload).await {
            error!(error = %e, "Failed to write to durable outbox in send_payload -- this batch may be lost");
        }
        let pending = match self.outbox.read_all().await {
            Ok(p) if !p.is_empty() => p,
            _ => return,
        };
        let mut s = self.stream.lock().await;
        let send_ok = if let Some(ref mut conn) = *s {
            match timeout(Duration::from_secs(30), conn.write_all(pending.as_bytes())).await {
                Ok(Ok(())) => true,
                Ok(Err(e)) => {
                    error!(error = %e, "Send failed -- data remains safely queued in durable outbox");
                    *s = None;
                    false
                }
                Err(_) => {
                    warn!(bytes = pending.len(), "Send timed out after 30s -- data remains safely queued in durable outbox");
                    *s = None;
                    false
                }
            }
        } else {
            false
        };
        drop(s);
        if send_ok {
            info!(bytes = pending.len(), "Flushed via durable outbox");
            if let Err(e) = self.outbox.clear().await {
                error!(error = %e, "Failed to clear durable outbox after successful send");
            }
        }
    }
}
