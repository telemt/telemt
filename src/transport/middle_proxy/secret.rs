use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::{ProxyError, Result};

/// Fetch Telegram proxy-secret binary.
pub async fn fetch_proxy_secret(cache_path: Option<&str>) -> Result<Vec<u8>> {
    let cache = cache_path.unwrap_or("proxy-secret");

    // 1) Try fresh download first.
    match download_proxy_secret().await {
        Ok(data) => {
            if let Err(e) = tokio::fs::write(cache, &data).await {
                warn!(error = %e, "Failed to cache proxy-secret (non-fatal)");
            } else {
                debug!(path = cache, len = data.len(), "Cached proxy-secret");
            }
            return Ok(data);
        }
        Err(download_err) => {
            warn!(error = %download_err, "Proxy-secret download failed, trying cache/file fallback");
            // Fall through to cache/file.
        }
    }

    // 2) Fallback to cache/file regardless of age; require len>=32.
    match tokio::fs::read(cache).await {
        Ok(data) if data.len() >= 32 => {
            let age_hours = tokio::fs::metadata(cache)
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|m| std::time::SystemTime::now().duration_since(m).ok())
                .map(|d| d.as_secs() / 3600);
            info!(
                path = cache,
                len = data.len(),
                age_hours,
                "Loaded proxy-secret from cache/file after download failure"
            );
            Ok(data)
        }
        Ok(data) => Err(ProxyError::Proxy(format!(
            "Cached proxy-secret too short: {} bytes (need >= 32)",
            data.len()
        ))),
        Err(e) => Err(ProxyError::Proxy(format!(
            "Failed to read proxy-secret cache after download failure: {e}"
        ))),
    }
}

pub async fn download_proxy_secret() -> Result<Vec<u8>> {
    let resp = reqwest::get("https://core.telegram.org/getProxySecret")
        .await
        .map_err(|e| ProxyError::Proxy(format!("Failed to download proxy-secret: {e}")))?;

    if !resp.status().is_success() {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret download HTTP {}",
            resp.status()
        )));
    }

    let data = resp
        .bytes()
        .await
        .map_err(|e| ProxyError::Proxy(format!("Read proxy-secret body: {e}")))?
        .to_vec();

    if data.len() < 32 {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too short: {} bytes (need >= 32)",
            data.len()
        )));
    }

    info!(len = data.len(), "Downloaded proxy-secret OK");
    Ok(data)
}
