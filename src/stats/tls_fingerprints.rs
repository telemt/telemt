//! Bounded TLS JA3/JA4 fingerprint aggregation.

use std::cmp::Reverse;
use std::hash::Hash;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::protocol::tls_fingerprint::TlsClientFingerprint;

use super::Stats;

const CLEANUP_INTERVAL_SECS: u64 = 30;
const MAX_TLS_FINGERPRINT_BUCKETS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TlsFingerprintScopeKind {
    Fingerprint,
    Ip,
    Cidr,
    User,
}

#[derive(Clone, Debug)]
pub struct TlsFingerprintSnapshotRow {
    pub scope_key: String,
    pub ja3: String,
    pub ja3_raw: String,
    pub ja4: String,
    pub ja4_raw: String,
    pub total: u64,
    pub auth_success: u64,
    pub bad_or_probe: u64,
    pub first_seen_epoch_secs: u64,
    pub last_seen_epoch_secs: u64,
}

#[derive(Clone, Debug)]
pub struct TlsFingerprintSnapshot {
    pub retention_secs: u64,
    pub capacity: usize,
    pub dropped_total: u64,
    pub parse_error_total: u64,
    pub by_fingerprint: Vec<TlsFingerprintSnapshotRow>,
    pub by_ip: Vec<TlsFingerprintSnapshotRow>,
    pub by_cidr: Vec<TlsFingerprintSnapshotRow>,
    pub by_user: Vec<TlsFingerprintSnapshotRow>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct TlsFingerprintKey {
    scope_kind: TlsFingerprintScopeKind,
    scope_key: String,
    ja3: String,
    ja3_raw: String,
    ja4: String,
    ja4_raw: String,
}

struct TlsFingerprintEntry {
    first_seen_epoch_secs: AtomicU64,
    last_seen_epoch_secs: AtomicU64,
    total: AtomicU64,
    auth_success: AtomicU64,
    bad_or_probe: AtomicU64,
}

#[derive(Default)]
pub struct TlsFingerprintCollector {
    entries: DashMap<TlsFingerprintKey, TlsFingerprintEntry>,
    dropped_total: AtomicU64,
    parse_error_total: AtomicU64,
    last_cleanup_epoch_secs: AtomicU64,
}

impl TlsFingerprintCollector {
    pub fn record_observed(
        &self,
        fingerprint: &TlsClientFingerprint,
        peer_ip: IpAddr,
        ttl: Duration,
    ) {
        if ttl.is_zero() {
            return;
        }
        let now = now_epoch_secs();
        self.cleanup_if_needed(now, ttl.as_secs());
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Fingerprint, ""),
            fingerprint,
            now,
            true,
            false,
            false,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Ip, &peer_ip.to_string()),
            fingerprint,
            now,
            true,
            false,
            false,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Cidr, &cidr_bucket(peer_ip)),
            fingerprint,
            now,
            true,
            false,
            false,
        );
    }

    pub fn record_auth_success(
        &self,
        fingerprint: &TlsClientFingerprint,
        peer_ip: IpAddr,
        user: &str,
        ttl: Duration,
    ) {
        if ttl.is_zero() || user.is_empty() {
            return;
        }
        let now = now_epoch_secs();
        self.cleanup_if_needed(now, ttl.as_secs());
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Fingerprint, ""),
            fingerprint,
            now,
            false,
            true,
            false,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Ip, &peer_ip.to_string()),
            fingerprint,
            now,
            false,
            true,
            false,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Cidr, &cidr_bucket(peer_ip)),
            fingerprint,
            now,
            false,
            true,
            false,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::User, user),
            fingerprint,
            now,
            true,
            true,
            false,
        );
    }

    pub fn record_bad_or_probe(
        &self,
        fingerprint: &TlsClientFingerprint,
        peer_ip: IpAddr,
        ttl: Duration,
    ) {
        if ttl.is_zero() {
            return;
        }
        let now = now_epoch_secs();
        self.cleanup_if_needed(now, ttl.as_secs());
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Fingerprint, ""),
            fingerprint,
            now,
            false,
            false,
            true,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Ip, &peer_ip.to_string()),
            fingerprint,
            now,
            false,
            false,
            true,
        );
        self.record_scoped(
            scope_key(TlsFingerprintScopeKind::Cidr, &cidr_bucket(peer_ip)),
            fingerprint,
            now,
            false,
            false,
            true,
        );
    }

    pub fn increment_parse_error(&self) {
        self.parse_error_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self, ttl: Duration, limit: usize) -> TlsFingerprintSnapshot {
        let now = now_epoch_secs();
        self.cleanup(now, ttl.as_secs());

        let limit = limit.clamp(1, 1000);
        let mut by_fingerprint = Vec::new();
        let mut by_ip = Vec::new();
        let mut by_cidr = Vec::new();
        let mut by_user = Vec::new();

        for entry in self.entries.iter() {
            let row = snapshot_row(entry.key(), entry.value());
            match entry.key().scope_kind {
                TlsFingerprintScopeKind::Fingerprint => by_fingerprint.push(row),
                TlsFingerprintScopeKind::Ip => by_ip.push(row),
                TlsFingerprintScopeKind::Cidr => by_cidr.push(row),
                TlsFingerprintScopeKind::User => by_user.push(row),
            }
        }

        sort_and_truncate(&mut by_fingerprint, limit);
        sort_and_truncate(&mut by_ip, limit);
        sort_and_truncate(&mut by_cidr, limit);
        sort_and_truncate(&mut by_user, limit);

        TlsFingerprintSnapshot {
            retention_secs: ttl.as_secs(),
            capacity: MAX_TLS_FINGERPRINT_BUCKETS,
            dropped_total: self.dropped_total.load(Ordering::Relaxed),
            parse_error_total: self.parse_error_total.load(Ordering::Relaxed),
            by_fingerprint,
            by_ip,
            by_cidr,
            by_user,
        }
    }

    pub fn snapshot_text(&self, ttl: Duration, limit: usize) -> String {
        let snapshot = self.snapshot(ttl, limit);
        if snapshot.by_fingerprint.is_empty()
            && snapshot.by_ip.is_empty()
            && snapshot.by_cidr.is_empty()
            && snapshot.by_user.is_empty()
        {
            return String::new();
        }

        let mut out = String::new();
        out.push_str("[tls_fingerprints]\n");
        out.push_str(&format!(
            "retention_secs={} capacity={} dropped_total={} parse_error_total={}\n",
            snapshot.retention_secs,
            snapshot.capacity,
            snapshot.dropped_total,
            snapshot.parse_error_total
        ));
        append_rows(
            &mut out,
            "tls_fingerprints.by_fingerprint",
            &snapshot.by_fingerprint,
        );
        append_rows(&mut out, "tls_fingerprints.by_ip", &snapshot.by_ip);
        append_rows(&mut out, "tls_fingerprints.by_cidr", &snapshot.by_cidr);
        append_rows(&mut out, "tls_fingerprints.by_user", &snapshot.by_user);
        out
    }

    fn record_scoped(
        &self,
        scope: (TlsFingerprintScopeKind, String),
        fingerprint: &TlsClientFingerprint,
        now_epoch_secs: u64,
        count_total: bool,
        count_auth_success: bool,
        count_bad_or_probe: bool,
    ) {
        let key = TlsFingerprintKey {
            scope_kind: scope.0,
            scope_key: scope.1,
            ja3: fingerprint.ja3.clone(),
            ja3_raw: fingerprint.ja3_raw.clone(),
            ja4: fingerprint.ja4.clone(),
            ja4_raw: fingerprint.ja4_raw.clone(),
        };

        if let Some(entry) = self.entries.get(&key) {
            update_entry(
                entry.value(),
                now_epoch_secs,
                count_total,
                count_auth_success,
                count_bad_or_probe,
            );
            return;
        }

        if self.entries.len() >= MAX_TLS_FINGERPRINT_BUCKETS {
            self.dropped_total.fetch_add(1, Ordering::Relaxed);
            return;
        }

        match self.entries.entry(key) {
            Entry::Occupied(entry) => {
                update_entry(
                    entry.get(),
                    now_epoch_secs,
                    count_total,
                    count_auth_success,
                    count_bad_or_probe,
                );
            }
            Entry::Vacant(entry) => {
                entry.insert(TlsFingerprintEntry::new(
                    now_epoch_secs,
                    if count_total { 1 } else { 0 },
                    if count_auth_success { 1 } else { 0 },
                    if count_bad_or_probe { 1 } else { 0 },
                ));
            }
        }
    }

    fn cleanup_if_needed(&self, now_epoch_secs: u64, ttl_secs: u64) {
        let last = self.last_cleanup_epoch_secs.load(Ordering::Relaxed);
        if now_epoch_secs.saturating_sub(last) < CLEANUP_INTERVAL_SECS {
            return;
        }
        if self
            .last_cleanup_epoch_secs
            .compare_exchange(last, now_epoch_secs, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.cleanup(now_epoch_secs, ttl_secs);
    }

    fn cleanup(&self, now_epoch_secs: u64, ttl_secs: u64) {
        if ttl_secs == 0 {
            self.entries.clear();
            return;
        }
        self.entries.retain(|_, entry| {
            let last_seen = entry.last_seen_epoch_secs.load(Ordering::Relaxed);
            now_epoch_secs.saturating_sub(last_seen) <= ttl_secs
        });
    }
}

impl TlsFingerprintEntry {
    fn new(now_epoch_secs: u64, total: u64, auth_success: u64, bad_or_probe: u64) -> Self {
        Self {
            first_seen_epoch_secs: AtomicU64::new(now_epoch_secs),
            last_seen_epoch_secs: AtomicU64::new(now_epoch_secs),
            total: AtomicU64::new(total),
            auth_success: AtomicU64::new(auth_success),
            bad_or_probe: AtomicU64::new(bad_or_probe),
        }
    }
}

fn update_entry(
    entry: &TlsFingerprintEntry,
    now_epoch_secs: u64,
    count_total: bool,
    count_auth_success: bool,
    count_bad_or_probe: bool,
) {
    entry
        .last_seen_epoch_secs
        .store(now_epoch_secs, Ordering::Relaxed);
    if count_total {
        entry.total.fetch_add(1, Ordering::Relaxed);
    }
    if count_auth_success {
        entry.auth_success.fetch_add(1, Ordering::Relaxed);
    }
    if count_bad_or_probe {
        entry.bad_or_probe.fetch_add(1, Ordering::Relaxed);
    }
}

fn snapshot_row(key: &TlsFingerprintKey, entry: &TlsFingerprintEntry) -> TlsFingerprintSnapshotRow {
    TlsFingerprintSnapshotRow {
        scope_key: key.scope_key.clone(),
        ja3: key.ja3.clone(),
        ja3_raw: key.ja3_raw.clone(),
        ja4: key.ja4.clone(),
        ja4_raw: key.ja4_raw.clone(),
        total: entry.total.load(Ordering::Relaxed),
        auth_success: entry.auth_success.load(Ordering::Relaxed),
        bad_or_probe: entry.bad_or_probe.load(Ordering::Relaxed),
        first_seen_epoch_secs: entry.first_seen_epoch_secs.load(Ordering::Relaxed),
        last_seen_epoch_secs: entry.last_seen_epoch_secs.load(Ordering::Relaxed),
    }
}

fn sort_and_truncate(rows: &mut Vec<TlsFingerprintSnapshotRow>, limit: usize) {
    rows.sort_by_key(|row| {
        (
            Reverse(row.total),
            row.scope_key.clone(),
            row.ja4.clone(),
            row.ja3.clone(),
        )
    });
    rows.truncate(limit);
}

fn append_rows(out: &mut String, section: &str, rows: &[TlsFingerprintSnapshotRow]) {
    if rows.is_empty() {
        return;
    }
    out.push('[');
    out.push_str(section);
    out.push_str("]\n");
    for row in rows {
        if row.scope_key.is_empty() {
            out.push_str(&format!(
                "ja4={} ja3={} total={} auth_success={} bad_or_probe={} first_seen={} last_seen={}\n",
                row.ja4,
                row.ja3,
                row.total,
                row.auth_success,
                row.bad_or_probe,
                row.first_seen_epoch_secs,
                row.last_seen_epoch_secs
            ));
        } else {
            out.push_str(&format!(
                "scope={} ja4={} ja3={} total={} auth_success={} bad_or_probe={} first_seen={} last_seen={}\n",
                row.scope_key,
                row.ja4,
                row.ja3,
                row.total,
                row.auth_success,
                row.bad_or_probe,
                row.first_seen_epoch_secs,
                row.last_seen_epoch_secs
            ));
        }
    }
}

fn scope_key(kind: TlsFingerprintScopeKind, key: &str) -> (TlsFingerprintScopeKind, String) {
    (kind, key.to_string())
}

fn cidr_bucket(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            format!("{a}.{b}.{c}.0/24")
        }
        IpAddr::V6(ip) => {
            let mut octets = ip.octets();
            for byte in &mut octets[7..] {
                *byte = 0;
            }
            format!("{}/56", Ipv6Addr::from(octets))
        }
    }
}

fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl Stats {
    pub fn record_tls_fingerprint_observed(
        &self,
        fingerprint: &TlsClientFingerprint,
        peer_ip: IpAddr,
        ttl: Duration,
    ) {
        if self.telemetry_core_enabled() {
            self.tls_fingerprints
                .record_observed(fingerprint, peer_ip, ttl);
        }
    }

    pub fn record_tls_fingerprint_auth_success(
        &self,
        fingerprint: &TlsClientFingerprint,
        peer_ip: IpAddr,
        user: &str,
        ttl: Duration,
    ) {
        if self.telemetry_core_enabled() {
            self.tls_fingerprints
                .record_auth_success(fingerprint, peer_ip, user, ttl);
        }
    }

    pub fn record_tls_fingerprint_bad_or_probe(
        &self,
        fingerprint: &TlsClientFingerprint,
        peer_ip: IpAddr,
        ttl: Duration,
    ) {
        if self.telemetry_core_enabled() {
            self.tls_fingerprints
                .record_bad_or_probe(fingerprint, peer_ip, ttl);
        }
    }

    pub fn increment_tls_fingerprint_parse_error(&self) {
        if self.telemetry_core_enabled() {
            self.tls_fingerprints.increment_parse_error();
        }
    }

    pub fn tls_fingerprint_snapshot(&self, ttl: Duration, limit: usize) -> TlsFingerprintSnapshot {
        self.tls_fingerprints.snapshot(ttl, limit)
    }

    pub fn tls_fingerprint_snapshot_text(&self, ttl: Duration, limit: usize) -> String {
        self.tls_fingerprints.snapshot_text(ttl, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fp() -> TlsClientFingerprint {
        TlsClientFingerprint {
            ja3: "ja3".to_string(),
            ja3_raw: "771,4865,,,0".to_string(),
            ja4: "t13d010100_hash_hash".to_string(),
            ja4_raw: "raw".to_string(),
        }
    }

    #[test]
    fn aggregates_ip_cidr_and_user_scopes() {
        let collector = TlsFingerprintCollector::default();
        let ip: IpAddr = "192.0.2.15".parse().expect("test IP parses");
        collector.record_observed(&fp(), ip, Duration::from_secs(60));
        collector.record_auth_success(&fp(), ip, "alice", Duration::from_secs(60));
        let snapshot = collector.snapshot(Duration::from_secs(60), 10);

        assert_eq!(snapshot.by_fingerprint[0].total, 1);
        assert_eq!(snapshot.by_fingerprint[0].auth_success, 1);
        assert_eq!(snapshot.by_ip[0].scope_key, "192.0.2.15");
        assert_eq!(snapshot.by_cidr[0].scope_key, "192.0.2.0/24");
        assert_eq!(snapshot.by_user[0].scope_key, "alice");
        assert_eq!(snapshot.by_user[0].total, 1);
    }
}
