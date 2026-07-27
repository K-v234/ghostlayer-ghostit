use sha2::{Sha256, Digest};
use tracing::{info, warn, error};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn is_newer_version(remote: &str, current: &str) -> bool {
    fn parse(v: &str) -> Vec<u32> {
        v.split('.').filter_map(|p| p.parse().ok()).collect()
    }
    let r = parse(remote);
    let c = parse(current);
    for i in 0..3 {
        let rv = r.get(i).copied().unwrap_or(0);
        let cv = c.get(i).copied().unwrap_or(0);
        if rv > cv { return true; }
        if rv < cv { return false; }
    }
    false
}

pub async fn check_and_apply_update(pipeline_host: &str, current_binary_path: &str) {
    let url = format!("http://{}:8000/agent/version", pipeline_host);

    let resp = match reqwest::get(&url).await {
        Ok(r) => r,
        Err(e) => {
            warn!(error = %e, "Update check failed -- will retry next cycle");
            return;
        }
    };

    let info_json: serde_json::Value = match resp.json().await {
        Ok(j) => j,
        Err(e) => {
            warn!(error = %e, "Update check response was not valid JSON");
            return;
        }
    };

    if info_json.get("available").and_then(|v| v.as_bool()) != Some(true) {
        return;
    }

    let remote_hash = match info_json.get("sha256").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => {
            warn!("Update check response missing sha256 -- refusing to proceed");
            return;
        }
    };
    let remote_version = info_json.get("version").and_then(|v| v.as_str()).unwrap_or("0.0.0");
    let current_version = env!("CARGO_PKG_VERSION");
    if !is_newer_version(remote_version, current_version) {
        return;
    }

    let current_bytes = match std::fs::read(current_binary_path) {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "Could not read own binary for hash comparison");
            return;
        }
    };
    let current_hash = hex_encode(&Sha256::digest(&current_bytes));

    if current_hash == remote_hash {
        return;
    }

    info!(current = %current_hash, remote = %remote_hash,
          "Newer agent version detected -- downloading real update");

    let download_url = format!("http://{}:8000/agent/download", pipeline_host);
    let downloaded = match reqwest::get(&download_url).await {
        Ok(r) => match r.bytes().await {
            Ok(b) => b,
            Err(e) => { error!(error = %e, "Update download body read failed"); return; }
        },
        Err(e) => { error!(error = %e, "Update download request failed"); return; }
    };

    let downloaded_hash = hex_encode(&Sha256::digest(&downloaded));
    if downloaded_hash != remote_hash {
        error!(expected = %remote_hash, got = %downloaded_hash,
               "Downloaded update hash mismatch -- refusing to apply, possible tampering or corruption");
        return;
    }

    let tmp_path = format!("{}.new", current_binary_path);
    if let Err(e) = std::fs::write(&tmp_path, &downloaded) {
        error!(error = %e, "Failed to write downloaded update to disk");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755));
    }
    if let Err(e) = std::fs::rename(&tmp_path, current_binary_path) {
        error!(error = %e, "Failed to atomically replace binary — old version remains active");
        let _ = std::fs::remove_file(&tmp_path);
        return;
    }

    info!("Update applied successfully — exiting cleanly for systemd to restart with the new version");
    std::process::exit(0);
}

pub fn spawn_update_checker(pipeline_host: String, binary_path: String) {
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        loop {
            check_and_apply_update(&pipeline_host, &binary_path).await;
            tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)).await;
        }
    });
}
