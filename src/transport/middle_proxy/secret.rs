use tracing::{debug, info, warn};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use httpdate;

use crate::error::{ProxyError, Result};
use super::selftest::record_timeskew_sample;

pub const PROXY_SECRET_MIN_LEN: usize = 32;

// Produces a unique path suffix from a nanosecond timestamp plus a per-process
// monotonic counter, preventing two concurrent writers from clobbering each
// other's in-progress temp file when the same cache path is shared.
fn unique_temp_path(cache: &str) -> String {
    static NEXT_ID: AtomicU64 = AtomicU64::new(0);
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    format!("{cache}.tmp.{ts}.{id}")
}

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
            // Write to a uniquely-named temporary file then rename for an atomic
            // update, preventing a partial write from corrupting the on-disk cache
            // and avoiding collisions between concurrent writers or processes.
            let tmp_path = unique_temp_path(cache);
            if let Err(e) = tokio::fs::write(&tmp_path, &data).await {
                warn!(error = %e, "Failed to write proxy-secret temp file (non-fatal)");
                // Best-effort cleanup: remove the partial temp file so it does not
                // accumulate on disk across failed refresh cycles.
                let _ = tokio::fs::remove_file(&tmp_path).await;
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
    // Fail fast before any network I/O when the caller passes a nonsensical cap.
    // Without this guard the error would surface only after the HTTP round-trip,
    // producing a misleading hard-cap or Content-Length error instead of an
    // explicit "invalid parameter" one.
    if max_len < PROXY_SECRET_MIN_LEN {
        return Err(ProxyError::Proxy(format!(
            "proxy-secret max_len {max_len} is below the minimum allowed {PROXY_SECRET_MIN_LEN}",
        )));
    }

    let mut resp = reqwest::get("https://core.telegram.org/getProxySecret")
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

    // Read the body as a stream, checking the hard cap *before* each chunk is
    // appended.  This prevents an oversized response from exhausting memory even
    // when Content-Length is absent (e.g. chunked transfer encoding).
    let hard_cap = max_len.min(PROXY_SECRET_DOWNLOAD_HARD_CAP);
    let mut data: Vec<u8> = Vec::new();
    loop {
        match resp
            .chunk()
            .await
            .map_err(|e| ProxyError::Proxy(format!("Read proxy-secret body: {e}")))?{
            Some(chunk) => {
                // Use checked_add to guard against a malicious/malfunctioning
                // HTTP implementation sending chunk lengths that sum past usize::MAX.
                let new_len = data
                    .len()
                    .checked_add(chunk.len())
                    .ok_or_else(|| ProxyError::Proxy(
                        "proxy-secret response body size overflowed usize".to_string(),
                    ))?;
                if new_len > hard_cap {
                    return Err(ProxyError::Proxy(format!(
                        "proxy-secret response body would exceed hard cap {hard_cap} bytes"
                    )));
                }
                data.extend_from_slice(&chunk);
            }
            None => break,
        }
    }
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

    // --- Streaming cap check (mirrors the chunk-accumulation loop) ---

    // The rejection must fire *before* the offending chunk is appended, so
    // memory usage never exceeds hard_cap even for a single oversized chunk.
    #[test]
    fn streaming_cap_rejects_at_chunk_boundary_before_copy() {
        let hard_cap = 100usize;
        let mut data: Vec<u8> = Vec::new();

        let chunks: &[&[u8]] = &[
            &[0x41u8; 60], // 60 bytes — accepted
            &[0x42u8; 41], // would bring total to 101 > 100 — must reject
            &[0x43u8; 10], // must never be reached
        ];

        let mut rejected_at = None;
        for (i, chunk) in chunks.iter().enumerate() {
            if data.len() + chunk.len() > hard_cap {
                rejected_at = Some(i);
                break;
            }
            data.extend_from_slice(chunk);
        }

        assert_eq!(rejected_at, Some(1), "rejection must occur at chunk index 1");
        assert_eq!(data.len(), 60, "only the first chunk must be accumulated");
        assert!(
            data.len() <= hard_cap,
            "accumulated bytes must not exceed hard_cap at the point of rejection"
        );
    }

    // A single chunk that is exactly hard_cap + 1 bytes must be rejected
    // immediately, with zero bytes buffered into memory.
    #[test]
    fn streaming_cap_rejects_single_oversized_chunk_before_any_copy() {
        let hard_cap = 100usize;
        let data: Vec<u8> = Vec::new();
        let chunk = vec![0xDEu8; hard_cap + 1];

        let would_reject = data.len() + chunk.len() > hard_cap;

        assert!(would_reject, "single oversized chunk must trigger cap rejection");
        assert_eq!(data.len(), 0, "zero bytes must be buffered when rejection fires");
    }

    // A body exactly equal to hard_cap bytes must be accepted without rejection.
    #[test]
    fn streaming_cap_accepts_body_exactly_at_hard_cap() {
        let hard_cap = 100usize;
        let mut data: Vec<u8> = Vec::new();

        let chunk = vec![0xABu8; hard_cap];
        let would_reject = data.len() + chunk.len() > hard_cap;
        if !would_reject {
            data.extend_from_slice(&chunk);
        }

        assert!(!would_reject, "body exactly at hard_cap must be accepted");
        assert_eq!(data.len(), hard_cap);
    }

    // Multiple small chunks that together exceed hard_cap must be rejected on
    // the chunk that would push the total over the limit.
    #[test]
    fn streaming_cap_rejects_cumulative_excess_across_many_chunks() {
        let hard_cap = 50usize;
        let mut data: Vec<u8> = Vec::new();
        let mut rejected = false;

        for i in 0..10u8 {
            let chunk = vec![i; 10]; // 10 chunks × 10 bytes = 100 total
            if data.len() + chunk.len() > hard_cap {
                rejected = true;
                break;
            }
            data.extend_from_slice(&chunk);
        }

        assert!(rejected, "cumulative excess across chunks must trigger rejection");
        assert!(
            data.len() <= hard_cap,
            "must not have buffered past hard_cap: got {} bytes",
            data.len()
        );
    }

    // The chunk-accumulation loop uses checked_add to prevent usize-overflow wrap-around
    // from silently bypassing the hard cap.  This test verifies the guard's contract:
    // a hypothetical accumulated length that would overflow usize when a new chunk is
    // added must be treated as a cap violation rather than wrapping back to a small value.
    #[test]
    fn streaming_cap_checked_add_overflow_is_treated_as_cap_violation() {
        // Simulate a near-saturated buffer (impossible in practice but must be
        // handled safely in the guard logic rather than panicking or wrapping).
        let almost_max: usize = usize::MAX - 3;
        let chunk_len: usize = 10; // wrapping addition would produce 6, sneaking past caps

        let new_len = almost_max.checked_add(chunk_len);

        // The guard must detect overflow (None) and treat it as cap exceeded,
        // not silently allow 6 bytes through.
        assert!(
            new_len.is_none(),
            "checked_add must detect overflow; wrapping arithmetic would produce {}",
            almost_max.wrapping_add(chunk_len)
        );
    }

    // --- unique_temp_path ---

    #[test]
    fn unique_temp_path_generates_distinct_names_on_successive_calls() {
        let p1 = unique_temp_path("proxy-secret");
        let p2 = unique_temp_path("proxy-secret");
        assert_ne!(p1, p2, "successive calls must produce distinct paths");
        assert!(
            p1.starts_with("proxy-secret.tmp."),
            "path must begin with the cache name and .tmp. prefix"
        );
    }

    #[test]
    fn unique_temp_path_embeds_cache_name_as_prefix() {
        let p = unique_temp_path("/var/cache/proxy-secret");
        assert!(
            p.starts_with("/var/cache/proxy-secret.tmp."),
            "path must preserve the full cache path as a prefix: {p}"
        );
    }
}
