use httpdate;
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, info, warn};

use super::http_fetch::https_get;
use super::selftest::record_timeskew_sample;
use crate::error::{ProxyError, Result};
use crate::transport::UpstreamManager;

pub const PROXY_SECRET_MIN_LEN: usize = 32;

pub(super) fn validate_proxy_secret_len(data_len: usize, max_len: usize) -> Result<()> {
    if max_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret max length is invalid: {} bytes (must be >= {})",
            max_len, PROXY_SECRET_MIN_LEN
        )));
    }

    if data_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too short: {} bytes (need >= {})",
            data_len, PROXY_SECRET_MIN_LEN
        )));
    }

    if data_len > max_len {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too long: {} bytes (limit = {})",
            data_len, max_len
        )));
    }

    Ok(())
}

/// Fetch Telegram proxy-secret binary.
#[allow(dead_code)]
pub async fn fetch_proxy_secret(cache_path: Option<&str>, max_len: usize) -> Result<Vec<u8>> {
    fetch_proxy_secret_with_upstream(cache_path, max_len, None).await
}

/// Fetch Telegram proxy-secret binary, optionally through upstream routing.
pub async fn fetch_proxy_secret_with_upstream(
    cache_path: Option<&str>,
    max_len: usize,
    upstream: Option<Arc<UpstreamManager>>,
) -> Result<Vec<u8>> {
    let cache = cache_path.unwrap_or("proxy-secret");

    // 1) Try fresh download first.
    match download_proxy_secret_with_max_len_via_upstream(max_len, upstream).await {
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

#[allow(dead_code)]
pub async fn download_proxy_secret_with_max_len(max_len: usize) -> Result<Vec<u8>> {
    download_proxy_secret_with_max_len_via_upstream(max_len, None).await
}

pub async fn download_proxy_secret_with_max_len_via_upstream(
    max_len: usize,
    upstream: Option<Arc<UpstreamManager>>,
) -> Result<Vec<u8>> {
    let resp = https_get("https://core.telegram.org/getProxySecret", upstream).await?;

    if !(200..=299).contains(&resp.status) {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret download HTTP {}",
            resp.status
        )));
    }

    if let Some(date_str) = resp.date_header.as_deref()
        && let Ok(server_time) = httpdate::parse_http_date(date_str)
        && let Ok(skew) = SystemTime::now()
            .duration_since(server_time)
            .or_else(|e| server_time.duration_since(SystemTime::now()).map_err(|_| e))
    {
        let skew_secs = skew.as_secs();
        record_timeskew_sample("proxy_secret_date_header", skew_secs);
        if skew_secs > 60 {
            warn!(
                skew_secs,
                "Time skew >60s detected from proxy-secret Date header"
            );
        } else if skew_secs > 30 {
            warn!(
                skew_secs,
                "Time skew >30s detected from proxy-secret Date header"
            );
        }
    }

    let data = resp.body;

    validate_proxy_secret_len(data.len(), max_len)?;

    info!(len = data.len(), "Downloaded proxy-secret OK");
    Ok(data)
}
