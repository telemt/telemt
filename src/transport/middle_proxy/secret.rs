use tracing::{debug, info, warn};
use std::time::SystemTime;
use httpdate;

use crate::error::{ProxyError, Result};

pub const PROXY_SECRET_MIN_LEN: usize = 32;

pub(super) fn validate_proxy_secret_len(data_len: usize, max_len: usize) -> Result<()> {
    if max_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret max length is invalid: {} bytes (must be >= {})",
            max_len,
            PROXY_SECRET_MIN_LEN
        )));
    }

    if data_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too short: {} bytes (need >= {})",
            data_len,
            PROXY_SECRET_MIN_LEN
        )));
    }

    if data_len > max_len {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too long: {} bytes (limit = {})",
            data_len,
            max_len
        )));
    }

    Ok(())
}

/// Fetch Telegram proxy-secret binary.
pub async fn fetch_proxy_secret(cache_path: Option<&str>, max_len: usize) -> Result<Vec<u8>> {
    let cache = cache_path.unwrap_or("proxy-secret");

    // 1) Try fresh download first.
    match download_proxy_secret_with_max_len(max_len).await {
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

    // 2) Fallback to cache/file regardless of age; require len in bounds.
    match tokio::fs::read(cache).await {
        Ok(data) if validate_proxy_secret_len(data.len(), max_len).is_ok() => {
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
        Ok(data) => validate_proxy_secret_len(data.len(), max_len).map(|_| data),
        Err(e) => Err(ProxyError::Proxy(format!(
            "Failed to read proxy-secret cache after download failure: {e}"
        ))),
    }
}

pub async fn download_proxy_secret_with_max_len(max_len: usize) -> Result<Vec<u8>> {
    let resp = reqwest::get("https://core.telegram.org/getProxySecret")
        .await
        .map_err(|e| ProxyError::Proxy(format!("Failed to download proxy-secret: {e}")))?;

    if !resp.status().is_success() {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret download HTTP {}",
            resp.status()
        )));
    }

    if let Some(date) = resp.headers().get(reqwest::header::DATE)
        && let Ok(date_str) = date.to_str()
        && let Ok(server_time) = httpdate::parse_http_date(date_str)
        && let Ok(skew) = SystemTime::now().duration_since(server_time).or_else(|e| {
            server_time.duration_since(SystemTime::now()).map_err(|_| e)
        })
    {
        let skew_secs = skew.as_secs();
        if skew_secs > 60 {
            warn!(skew_secs, "Time skew >60s detected from proxy-secret Date header");
        } else if skew_secs > 30 {
            warn!(skew_secs, "Time skew >30s detected from proxy-secret Date header");
        }
    }

    let data = resp
        .bytes()
        .await
        .map_err(|e| ProxyError::Proxy(format!("Read proxy-secret body: {e}")))?
        .to_vec();

    validate_proxy_secret_len(data.len(), max_len)?;

    info!(len = data.len(), "Downloaded proxy-secret OK");
    Ok(data)
}
