use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::*;
pub fn next_refill_delay() -> Duration {
    let start = limiter_epoch_start();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    let epoch_pos = elapsed_ms % FAIR_EPOCH_MS;
    let wait_ms = FAIR_EPOCH_MS.saturating_sub(epoch_pos).max(1);
    Duration::from_millis(wait_ms)
}

pub(super) fn decrement_atomic_saturating(counter: &AtomicU64, by: u64) {
    if by == 0 {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        if current == 0 {
            return;
        }
        let next = current.saturating_sub(by);
        match counter.compare_exchange_weak(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

pub(super) fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn bytes_per_epoch(bps: u64) -> u64 {
    if bps == 0 {
        return 0;
    }
    let numerator = bps.saturating_mul(FAIR_EPOCH_MS);
    let bytes = numerator.saturating_div(8_000);
    bytes.max(1)
}

pub(super) fn auto_cidr_bucket_key(ip: IpAddr, prefix_len: u8) -> Option<String> {
    let cidr = IpNetwork::new(ip, prefix_len).ok()?;
    let network = IpNetwork::new(cidr.network(), prefix_len).ok()?;
    let family = match network {
        IpNetwork::V4(_) => "4",
        IpNetwork::V6(_) => "6",
    };
    Some(format!("auto:{family}:{network}"))
}

pub(super) fn current_epoch() -> u64 {
    let start = limiter_epoch_start();
    let elapsed_ms = start.elapsed().as_millis() as u64;
    elapsed_ms / FAIR_EPOCH_MS
}

pub(super) fn limiter_epoch_start() -> &'static Instant {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now)
}
