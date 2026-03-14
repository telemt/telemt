use std::time::Duration;

use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::cli;
use crate::config::ProxyConfig;
use crate::transport::middle_proxy::{
    ProxyConfigData, fetch_proxy_config_with_raw, load_proxy_config_cache, save_proxy_config_cache,
};

pub(crate) fn parse_cli() -> (String, bool, Option<String>) {
    let mut config_path = "config.toml".to_string();
    let mut silent = false;
    let mut log_level: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();

    // Check for --init first (handled before tokio)
    if let Some(init_opts) = cli::parse_init_args(&args) {
        if let Err(e) = cli::run_init(init_opts) {
            eprintln!("[telemt] Init failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--silent" | "-s" => {
                silent = true;
            }
            "--log-level" => {
                i += 1;
                if i < args.len() {
                    log_level = Some(args[i].clone());
                }
            }
            s if s.starts_with("--log-level=") => {
                log_level = Some(s.trim_start_matches("--log-level=").to_string());
            }
            "--help" | "-h" => {
                eprintln!("Usage: telemt [config.toml] [OPTIONS]");
                eprintln!();
                eprintln!("Options:");
                eprintln!("  --silent, -s            Suppress info logs");
                eprintln!("  --log-level <LEVEL>     debug|verbose|normal|silent");
                eprintln!("  --help, -h              Show this help");
                eprintln!();
                eprintln!("Setup (fire-and-forget):");
                eprintln!(
                    "  --init                  Generate config, install systemd service, start"
                );
                eprintln!("    --port <PORT>          Listen port (default: 443)");
                eprintln!(
                    "    --domain <DOMAIN>      TLS domain for masking (default: www.google.com)"
                );
                eprintln!(
                    "    --secret <HEX>         32-char hex secret (auto-generated if omitted)"
                );
                eprintln!("    --user <NAME>          Username (default: user)");
                eprintln!("    --config-dir <DIR>     Config directory (default: /etc/telemt)");
                eprintln!("    --no-start             Don't start the service after install");
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("telemt {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            s if !s.starts_with('-') => {
                config_path = s.to_string();
            }
            other => {
                eprintln!("Unknown option: {}", other);
            }
        }
        i += 1;
    }

    (config_path, silent, log_level)
}

pub(crate) fn print_proxy_links(host: &str, port: u16, config: &ProxyConfig) {
    info!(target: "telemt::links", "--- Proxy Links ({}) ---", host);
    for user_name in config.general.links.show.resolve_users(&config.access.users) {
        if let Some(secret) = config.access.users.get(user_name) {
            info!(target: "telemt::links", "User: {}", user_name);
            if config.general.modes.classic {
                info!(
                    target: "telemt::links",
                    "  Classic: tg://proxy?server={}&port={}&secret={}",
                    host, port, secret
                );
            }
            if config.general.modes.secure {
                info!(
                    target: "telemt::links",
                    "  DD:      tg://proxy?server={}&port={}&secret=dd{}",
                    host, port, secret
                );
            }
            if config.general.modes.tls {
                let mut domains = Vec::with_capacity(1 + config.censorship.tls_domains.len());
                domains.push(config.censorship.tls_domain.clone());
                for d in &config.censorship.tls_domains {
                    if !domains.contains(d) {
                        domains.push(d.clone());
                    }
                }

                for domain in domains {
                    let domain_hex = hex::encode(&domain);
                    info!(
                        target: "telemt::links",
                        "  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                        host, port, secret, domain_hex
                    );
                }
            }
        } else {
            warn!(target: "telemt::links", "User '{}' in show_link not found", user_name);
        }
    }
    info!(target: "telemt::links", "------------------------");
}

pub(crate) async fn write_beobachten_snapshot(path: &str, payload: &str) -> std::io::Result<()> {
    if let Some(parent) = std::path::Path::new(path).parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, payload).await
}

pub(crate) const fn unit_label(
    value: u64,
    singular: &'static str,
    plural: &'static str,
) -> &'static str {
    if value == 1 { singular } else { plural }
}

pub(crate) fn format_uptime(total_secs: u64) -> String {
    const SECS_PER_MINUTE: u64 = 60;
    const SECS_PER_HOUR: u64 = 60 * SECS_PER_MINUTE;
    const SECS_PER_DAY: u64 = 24 * SECS_PER_HOUR;
    const SECS_PER_MONTH: u64 = 30 * SECS_PER_DAY;
    const SECS_PER_YEAR: u64 = 12 * SECS_PER_MONTH;

    let mut remaining = total_secs;
    let years = remaining / SECS_PER_YEAR;
    remaining %= SECS_PER_YEAR;
    let months = remaining / SECS_PER_MONTH;
    remaining %= SECS_PER_MONTH;
    let days = remaining / SECS_PER_DAY;
    remaining %= SECS_PER_DAY;
    let hours = remaining / SECS_PER_HOUR;
    remaining %= SECS_PER_HOUR;
    let minutes = remaining / SECS_PER_MINUTE;
    let seconds = remaining % SECS_PER_MINUTE;

    let mut parts = Vec::new();
    if years > 0 {
        parts.push(format!("{} {}", years, unit_label(years, "year", "years")));
    }
    if months > 0 {
        parts.push(format!(
            "{} {}",
            months,
            unit_label(months, "month", "months")
        ));
    }
    if days > 0 {
        parts.push(format!("{} {}", days, unit_label(days, "day", "days")));
    }
    if hours > 0 {
        parts.push(format!("{} {}", hours, unit_label(hours, "hour", "hours")));
    }
    if minutes > 0 {
        parts.push(format!(
            "{} {}",
            minutes,
            unit_label(minutes, "minute", "minutes")
        ));
    }
    // Show seconds when non-zero, or as the sole component when everything else is zero.
    if seconds > 0 || parts.is_empty() {
        parts.push(format!(
            "{} {}",
            seconds,
            unit_label(seconds, "second", "seconds")
        ));
    }

    format!("{} / {} seconds", parts.join(", "), total_secs)
}

pub(crate) async fn wait_until_admission_open(admission_rx: &mut watch::Receiver<bool>) -> bool {
    loop {
        if *admission_rx.borrow() {
            return true;
        }
        if admission_rx.changed().await.is_err() {
            return *admission_rx.borrow();
        }
    }
}

pub(crate) fn is_expected_handshake_eof(err: &crate::error::ProxyError) -> bool {
    matches!(
        err,
        crate::error::ProxyError::Stream(
            crate::error::StreamError::PartialRead { expected: 64, got: 0 }
        )
    )
}

/// Computes the exponential backoff delay in milliseconds for a given retry attempt.
///
/// Returns `min(base_ms * 2^(attempt - 1), cap_ms)`. Saturates on overflow.
/// `attempt` values of 0 are treated identically to 1 (returns `base_ms`).
pub(crate) fn retry_backoff_ms(attempt: u32, base_ms: u64, cap_ms: u64) -> u64 {
    let exp = attempt.saturating_sub(1).min(62);
    base_ms.saturating_mul(1u64 << exp).min(cap_ms)
}

pub(crate) async fn load_startup_proxy_config_snapshot(
    url: &str,
    cache_path: Option<&str>,
    me2dc_fallback: bool,
    label: &'static str,
    backoff_base_ms: u64,
    backoff_cap_ms: u64,
) -> Option<ProxyConfigData> {
    let mut fetch_attempt: u32 = 0;
    loop {
        fetch_attempt = fetch_attempt.saturating_add(1);
        match fetch_proxy_config_with_raw(url).await {
            Ok((cfg, raw)) => {
                if !cfg.map.is_empty() {
                    if let Some(path) = cache_path
                        && let Err(e) = save_proxy_config_cache(path, &raw).await
                    {
                        warn!(error = %e, path, snapshot = label, "Failed to store startup proxy-config cache");
                    }
                    return Some(cfg);
                }

                warn!(snapshot = label, url, "Startup proxy-config is empty; trying disk cache");
                if let Some(path) = cache_path {
                    match load_proxy_config_cache(path).await {
                        Ok(cached) if !cached.map.is_empty() => {
                            info!(
                                snapshot = label,
                                path,
                                proxy_for_lines = cached.proxy_for_lines,
                                "Loaded startup proxy-config from disk cache"
                            );
                            return Some(cached);
                        }
                        Ok(_) => {
                            warn!(
                                snapshot = label,
                                path,
                                "Startup proxy-config cache is empty; ignoring cache file"
                            );
                        }
                        Err(cache_err) => {
                            debug!(
                                snapshot = label,
                                path,
                                error = %cache_err,
                                "Startup proxy-config cache unavailable"
                            );
                        }
                    }
                }

                if me2dc_fallback {
                    error!(
                        snapshot = label,
                        "Startup proxy-config unavailable and no saved config found; falling back to direct mode"
                    );
                    return None;
                }

                warn!(
                    snapshot = label,
                    attempt = fetch_attempt,
                    retry_in_ms = retry_backoff_ms(fetch_attempt, backoff_base_ms, backoff_cap_ms),
                    "Startup proxy-config unavailable and no saved config found; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_millis(retry_backoff_ms(fetch_attempt, backoff_base_ms, backoff_cap_ms))).await;
            }
            Err(fetch_err) => {
                if let Some(path) = cache_path {
                    match load_proxy_config_cache(path).await {
                        Ok(cached) if !cached.map.is_empty() => {
                            info!(
                                snapshot = label,
                                path,
                                proxy_for_lines = cached.proxy_for_lines,
                                "Loaded startup proxy-config from disk cache"
                            );
                            return Some(cached);
                        }
                        Ok(_) => {
                            warn!(
                                snapshot = label,
                                path,
                                "Startup proxy-config cache is empty; ignoring cache file"
                            );
                        }
                        Err(cache_err) => {
                            debug!(
                                snapshot = label,
                                path,
                                error = %cache_err,
                                "Startup proxy-config cache unavailable"
                            );
                        }
                    }
                }

                if me2dc_fallback {
                    error!(
                        snapshot = label,
                        error = %fetch_err,
                        "Startup proxy-config unavailable and no cached data; falling back to direct mode"
                    );
                    return None;
                }

                warn!(
                    snapshot = label,
                    error = %fetch_err,
                    attempt = fetch_attempt,
                    retry_in_ms = retry_backoff_ms(fetch_attempt, backoff_base_ms, backoff_cap_ms),
                    "Startup proxy-config unavailable; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_millis(retry_backoff_ms(fetch_attempt, backoff_base_ms, backoff_cap_ms))).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{format_uptime, is_expected_handshake_eof, retry_backoff_ms, unit_label};

    // ── unit_label ────────────────────────────────────────────────────────────

    #[test]
    fn unit_label_singular_for_one() {
        assert_eq!(unit_label(1, "second", "seconds"), "second");
    }

    #[test]
    fn unit_label_plural_for_zero() {
        assert_eq!(unit_label(0, "second", "seconds"), "seconds");
    }

    #[test]
    fn unit_label_plural_for_two() {
        assert_eq!(unit_label(2, "minute", "minutes"), "minutes");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    // Returns the time-description part (before " / "), split on ", ".
    fn time_components(s: &str) -> Vec<&str> {
        s.split(" / ")
            .next()
            .unwrap_or("")
            .split(", ")
            .collect()
    }

    // Asserts that no component in the time-description starts with "0 ".
    fn assert_no_zero_components(s: &str) {
        for c in time_components(s) {
            assert!(!c.starts_with("0 "), "zero-valued component '{c}' in: {s}");
        }
    }

    // ── format_uptime: zero ───────────────────────────────────────────────────

    #[test]
    fn format_uptime_zero_shows_zero_seconds() {
        assert_eq!(format_uptime(0), "0 seconds / 0 seconds");
    }

    // ── format_uptime: sub-minute timestamps ─────────────────────────────────

    #[test]
    fn format_uptime_one_second() {
        assert_eq!(format_uptime(1), "1 second / 1 seconds");
    }

    #[test]
    fn format_uptime_59_seconds() {
        assert_eq!(format_uptime(59), "59 seconds / 59 seconds");
    }

    // ── format_uptime: exact unit boundaries must show no zero sub-units ──────
    //
    // The code's calendar: 1 min = 60 s, 1 hr = 3600 s, 1 day = 86 400 s,
    //   1 month = 30 days = 2 592 000 s, 1 year = 12 months = 31 104 000 s.

    #[test]
    fn format_uptime_exactly_one_minute_no_zero_components() {
        let s = format_uptime(60);
        assert_eq!(s, "1 minute / 60 seconds");
        assert_no_zero_components(&s);
    }

    #[test]
    fn format_uptime_exactly_one_hour_no_zero_components() {
        let s = format_uptime(3_600);
        assert_eq!(s, "1 hour / 3600 seconds");
        assert_no_zero_components(&s);
    }

    #[test]
    fn format_uptime_exactly_one_day_no_zero_components() {
        let s = format_uptime(86_400);
        assert_eq!(s, "1 day / 86400 seconds");
        assert_no_zero_components(&s);
    }

    #[test]
    fn format_uptime_exactly_one_month_no_zero_components() {
        // SECS_PER_MONTH = 30 * 86 400 = 2 592 000
        let s = format_uptime(2_592_000);
        assert_eq!(s, "1 month / 2592000 seconds");
        assert_no_zero_components(&s);
    }

    #[test]
    fn format_uptime_exactly_one_year_no_zero_components() {
        // SECS_PER_YEAR = 12 * 30 * 86 400 = 31 104 000
        let s = format_uptime(31_104_000);
        assert_eq!(s, "1 year / 31104000 seconds");
        assert_no_zero_components(&s);
    }

    // ── format_uptime: year + 1 second — the original regression case ─────────

    #[test]
    fn format_uptime_one_year_plus_one_second_no_zero_middle_units() {
        // Old guard `total_secs > SECS_PER_X` emitted every intermediate unit
        // even when zero, yielding:
        //   "1 year, 0 months, 0 days, 0 hours, 0 minutes, 1 second / ..."
        // With the fix only non-zero components appear.
        let total = 31_104_001u64; // SECS_PER_YEAR + 1
        let s = format_uptime(total);
        assert_eq!(s, format!("1 year, 1 second / {total} seconds"));
        assert_no_zero_components(&s);
    }

    // ── format_uptime: mixed & multi-component values ─────────────────────────

    #[test]
    fn format_uptime_mixed_components() {
        // 1 hour + 1 minute + 1 second = 3661 s
        let s = format_uptime(3_661);
        assert_eq!(s, "1 hour, 1 minute, 1 second / 3661 seconds");
        assert_no_zero_components(&s);
    }

    #[test]
    fn format_uptime_two_years_three_months_exact() {
        // Use model constants: 2*31_104_000 + 3*2_592_000 = 69_984_000 s
        let secs: u64 = 2 * 31_104_000 + 3 * 2_592_000;
        let s = format_uptime(secs);
        assert_eq!(s, format!("2 years, 3 months / {secs} seconds"));
        assert_no_zero_components(&s);
    }

    // ── format_uptime: exhaustive zero-component invariant ────────────────────

    #[test]
    fn format_uptime_no_component_is_zero_except_sole_seconds() {
        // For total_secs > 0, no time-description component may start with "0 ".
        let secs_per_minute: u64 = 60;
        let secs_per_hour: u64 = 60 * secs_per_minute;
        let secs_per_day: u64 = 24 * secs_per_hour;
        let secs_per_month: u64 = 30 * secs_per_day;
        let secs_per_year: u64 = 12 * secs_per_month;

        let candidates: &[u64] = &[
            0, 1, 59, 60, 61, 119, 120, 3599, 3600, 3601,
            86_399, 86_400, 86_401,
            secs_per_month - 1, secs_per_month, secs_per_month + 1,
            secs_per_year - 1, secs_per_year, secs_per_year + 1,
            secs_per_day + secs_per_hour,
            secs_per_day + secs_per_hour + secs_per_minute + 1,
            2 * secs_per_year + 1,
            u64::MAX / 2,
        ];

        for &t in candidates {
            let s = format_uptime(t);
            if t == 0 {
                assert_eq!(s, "0 seconds / 0 seconds");
                continue;
            }
            assert_no_zero_components(&s);
        }
    }

    // ── is_expected_handshake_eof ─────────────────────────────────────────────

    #[test]
    fn eof_match_accepts_partial_read_64_0() {
        use crate::error::{ProxyError, StreamError};
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 64, got: 0 });
        assert!(is_expected_handshake_eof(&err));
    }

    #[test]
    fn eof_match_rejects_wrong_expected_size() {
        use crate::error::{ProxyError, StreamError};
        // A 32-byte partial read is NOT the handshake EOF pattern.
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 32, got: 0 });
        assert!(!is_expected_handshake_eof(&err));
    }

    #[test]
    fn eof_match_rejects_nonzero_got() {
        use crate::error::{ProxyError, StreamError};
        // Received some bytes but not all — not a clean EOF.
        let err = ProxyError::Stream(StreamError::PartialRead { expected: 64, got: 1 });
        assert!(!is_expected_handshake_eof(&err));
    }

    #[test]
    fn eof_match_rejects_unexpected_eof_variant() {
        use crate::error::{ProxyError, StreamError};
        let err = ProxyError::Stream(StreamError::UnexpectedEof);
        assert!(!is_expected_handshake_eof(&err));
    }

    #[test]
    fn eof_match_rejects_unrelated_proxy_error() {
        use crate::error::ProxyError;
        let err = ProxyError::Internal("unrelated".to_string());
        assert!(!is_expected_handshake_eof(&err));
    }

    #[test]
    fn eof_match_rejects_tls_handshake_failed() {
        use crate::error::ProxyError;
        // Old string-based check would also reject this, but verifying structural safety.
        let err = ProxyError::TlsHandshakeFailed { reason: "expected 64 bytes, got 0".to_string() };
        assert!(!is_expected_handshake_eof(&err));
    }

    // ── retry_backoff_ms ──────────────────────────────────────────────────────

    #[test]
    fn backoff_first_attempt_is_base() {
        assert_eq!(retry_backoff_ms(1, 2_000, 60_000), 2_000);
    }

    #[test]
    fn backoff_doubles_each_attempt() {
        assert_eq!(retry_backoff_ms(2, 2_000, 60_000), 4_000);
        assert_eq!(retry_backoff_ms(3, 2_000, 60_000), 8_000);
        assert_eq!(retry_backoff_ms(4, 2_000, 60_000), 16_000);
        assert_eq!(retry_backoff_ms(5, 2_000, 60_000), 32_000);
    }

    #[test]
    fn backoff_clamped_at_cap() {
        // attempt=6: 2000 * 2^5 = 64_000 > 60_000, so it clamps.
        assert_eq!(retry_backoff_ms(6, 2_000, 60_000), 60_000);
        assert_eq!(retry_backoff_ms(100, 2_000, 60_000), 60_000);
    }

    #[test]
    fn backoff_zero_attempt_treated_as_first() {
        // saturating_sub(1) on 0 yields 0; result is base * 2^0 = base.
        assert_eq!(retry_backoff_ms(0, 2_000, 60_000), 2_000);
    }

    #[test]
    fn backoff_huge_attempt_does_not_overflow() {
        // exp is clamped to 62 to prevent shift overflow, then saturating_mul
        // prevents u64 overflow; .min(cap) brings it to cap.
        assert_eq!(retry_backoff_ms(u32::MAX, 2_000, 60_000), 60_000);
    }

    #[test]
    fn backoff_saturating_mul_does_not_panic() {
        // base near u64::MAX with a high attempt: saturating_mul returns u64::MAX,
        // .min(u64::MAX) keeps it at u64::MAX.
        assert_eq!(retry_backoff_ms(10, u64::MAX, u64::MAX), u64::MAX);
    }

    #[test]
    fn backoff_base_one_ms_progression() {
        // With base=1 and cap=1000:
        assert_eq!(retry_backoff_ms(1, 1, 1_000), 1);
        assert_eq!(retry_backoff_ms(10, 1, 1_000), 512);   // 1 * 2^9
        assert_eq!(retry_backoff_ms(11, 1, 1_000), 1_000); // 1 * 2^10 = 1024 > 1000, capped
    }

    #[test]
    fn backoff_cap_equal_to_base_always_returns_base() {
        for attempt in [1u32, 2, 5, 100] {
            assert_eq!(retry_backoff_ms(attempt, 5_000, 5_000), 5_000);
        }
    }
}
