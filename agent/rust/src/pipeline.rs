//! Pipeline forwarder — sends events to Ghost IT pipeline via TCP

use anyhow::Result;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error, debug};
use std::sync::Arc;
use tokio::sync::Mutex;

pub struct PipelineForwarder {
    host:             String,
    port:             u16,
    batch_size:       usize,
    flush_interval_ms: u64,
    batch:            Arc<Mutex<Vec<Value>>>,
    stream:           Arc<Mutex<Option<TcpStream>>>,
}

impl PipelineForwarder {
    pub async fn new(
        host: &str,
        port: u16,
        batch_size: usize,
        flush_interval_ms: u64,
    ) -> Result<Self> {
        let forwarder = Self {
            host:             host.to_string(),
            port,
            batch_size,
            flush_interval_ms,
            batch:            Arc::new(Mutex::new(Vec::new())),
            stream:           Arc::new(Mutex::new(None)),
        };

        forwarder.connect().await;
        forwarder.start_timer();
        Ok(forwarder)
    }

    async fn connect(&self) {
        match TcpStream::connect(format!("{}:{}", self.host, self.port)).await {
            Ok(s) => {
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

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_millis(ms));
            loop {
                ticker.tick().await;
                let mut b = batch.lock().await;
                if b.is_empty() {
                    continue;
                }
                let payload = format!("{}\n", serde_json::to_string(&*b).unwrap_or_default());
                b.clear();
                drop(b);

                let mut s = stream.lock().await;
                if let Some(ref mut conn) = *s {
                    if let Err(e) = conn.write_all(payload.as_bytes()).await {
                        warn!(error = %e, "Pipeline write failed — reconnecting");
                        *s = None;
                        // Reconnect on next event
                    }
                } else {
                    // Try reconnect
                    match TcpStream::connect(format!("{}:{}", host, port)).await {
                        Ok(conn) => {
                            info!("Pipeline reconnected");
                            *s = Some(conn);
                        }
                        Err(_) => {
                            // Print to stdout as fallback
                            print!("{}", payload);
                        }
                    }
                }
            }
        });
    }

    pub async fn forward(&mut self, event: Value) -> Result<()> {
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
        let mut s = self.stream.lock().await;
        if let Some(ref mut conn) = *s {
            if let Err(e) = conn.write_all(payload.as_bytes()).await {
                error!(error = %e, "Send failed");
                *s = None;
            } else {
                debug!(bytes = payload.len(), "Flushed");
            }
        } else {
            print!("{}", payload);
        }
    }
}
