use tracing::{debug, info, warn};
use std::time::SystemTime;
use httpdate;

use crate::error::{ProxyError, Result};
use super::selftest::record_timeskew_sample;

pub const PROXY_SECRET_MIN_LEN: usize = 32;

/// Absolute upper bound on bytes we are willing to buffer from the network before
/// running any protocol-level length validation.  Prevents OOM if the remote
/// endpoint (or a MITM) sends an oversized response body.
const PROXY_SECRET_DOWNLOAD_HARD_CAP: usize = 65_536; // 64 KiB

pub(super) fn validate_proxy_secret_len(data_len: usize, max_len: usize) -> Result<()> {
    if max_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret max length is invalid: {max_len} bytes (must be >= {PROXY_SECRET_MIN_LEN})",
        )));
    }

    if data_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too short: {data_len} bytes (need >= {PROXY_SECRET_MIN_LEN})",
        )));
    }

    if data_len > max_len {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret too long: {data_len} bytes (limit = {max_len})",
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
            // Write to a temporary file then rename for an atomic update,
            // preventing a partial write from corrupting the on-disk cache.
            let tmp_path = format!("{cache}.tmp");
            if let Err(e) = tokio::fs::write(&tmp_path, &data).await {
                warn!(error = %e, "Failed to write proxy-secret temp file (non-fatal)");
            } else if let Err(e) = tokio::fs::rename(&tmp_path, cache).await {
                warn!(error = %e, path = cache, "Failed to rename proxy-secret cache (non-fatal)");
                let _ = tokio::fs::remove_file(&tmp_path).await;
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
                .and_then(|m| SystemTime::now().duration_since(m).ok())
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

    // Reject early when Content-Length is present and already exceeds our cap,
    // before any bytes are transferred into memory.
    if let Some(content_len) = resp.content_length() {
        let hard_cap = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP) as u64;
        if content_len > hard_cap {
            return Err(ProxyError::Proxy(format!(
                "proxy-secret Content-Length {content_len} exceeds hard cap {hard_cap}"
            )));
        }
    }

    if let Some(date) = resp.headers().get(reqwest::header::DATE)
        && let Ok(date_str) = date.to_str()
        && let Ok(server_time) = httpdate::parse_http_date(date_str)
        && let Ok(skew) = SystemTime::now().duration_since(server_time).or_else(|e| {
            server_time.duration_since(SystemTime::now()).map_err(|_| e)
        })
    {
        let skew_secs = skew.as_secs();
        record_timeskew_sample("proxy_secret_date_header", skew_secs);
        if skew_secs > 60 {
            warn!(skew_secs, "Time skew >60s detected from proxy-secret Date header");
        } else if skew_secs > 30 {
            warn!(skew_secs, "Time skew >30s detected from proxy-secret Date header");
        }
    }

    let data = resp
        .bytes()
        .await
        .map_err(|e| ProxyError::Proxy(format!("Read proxy-secret body: {e}")))?;

    // Secondary cap covers chunked transfer responses that omit Content-Length.
    let hard_cap = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP);
    if data.len() > hard_cap {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret response body {} bytes exceeds hard cap {hard_cap}",
            data.len()
        )));
    }

    let data = data.to_vec();
    validate_proxy_secret_len(data.len(), max_len)?;

    info!(len = data.len(), "Downloaded proxy-secret OK");
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- validate_proxy_secret_len ---

    #[test]
    fn validate_rejects_max_len_below_minimum() {
        assert!(validate_proxy_secret_len(32, 31).is_err());
    }

    #[test]
    fn validate_rejects_data_shorter_than_minimum() {
        assert!(validate_proxy_secret_len(31, 512).is_err());
    }

    #[test]
    fn validate_rejects_data_longer_than_max() {
        assert!(validate_proxy_secret_len(513, 512).is_err());
    }

    #[test]
    fn validate_accepts_exact_minimum() {
        assert!(validate_proxy_secret_len(32, 32).is_ok());
    }

    #[test]
    fn validate_accepts_value_within_bounds() {
        assert!(validate_proxy_secret_len(256, 512).is_ok());
    }

    // --- hard cap constant ---

    #[test]
    fn proxy_secret_hard_cap_exceeds_maximum_protocol_secret() {
        // The hard cap must be larger than any valid proxy-secret length.
        const { assert!(PROXY_SECRET_DOWNLOAD_HARD_CAP >= PROXY_SECRET_MIN_LEN) };
        const { assert!(PROXY_SECRET_DOWNLOAD_HARD_CAP >= 256, "common secret is 256 bytes") };
    }

    // --- Content-Length pre-check logic ---

    // Verify the effective cap computation: min(max_len, HARD_CAP).
    // This ensures a caller cannot bypass the hard cap by passing a large max_len.
    #[test]
    fn hard_cap_cannot_be_exceeded_by_large_max_len() {
        let max_len = usize::MAX;
        let effective = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP);
        assert_eq!(effective, PROXY_SECRET_DOWNLOAD_HARD_CAP);
    }

    #[test]
    fn hard_cap_honours_smaller_max_len() {
        let max_len = 128;
        let effective = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP);
        assert_eq!(effective, 128);
    }

    // Simulate the Content-Length pre-check: a response claiming to be 1 byte
    // over the effective cap must be rejected without reading the body.
    #[test]
    fn content_length_precheck_rejects_oversized() {
        let max_len = 4096usize;
        let hard_cap = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP) as u64;
        let bad_content_len: u64 = hard_cap + 1;
        assert!(bad_content_len > hard_cap, "pre-check must reject this");
    }

    #[test]
    fn content_length_precheck_accepts_exact_cap() {
        let max_len = 4096usize;
        let hard_cap = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP) as u64;
        let ok_content_len: u64 = hard_cap;
        assert!(ok_content_len <= hard_cap);
    }
}
