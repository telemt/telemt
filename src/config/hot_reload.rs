//! Hot-reload: watches the config file via inotify (Linux) / FSEvents (macOS)
//! / ReadDirectoryChangesW (Windows) using the `notify` crate.
//! SIGHUP is also supported on Unix as an additional manual trigger.
//!
//! # What can be reloaded without restart
//!
//! | Section   | Field                          | Effect                                         |
//! |-----------|--------------------------------|------------------------------------------------|
//! | `general` | `log_level`                    | Filter updated via `log_level_tx`              |
//! | `access`  | `user_ad_tags`                 | Passed on next connection                      |
//! | `general` | `ad_tag`                       | Passed on next connection (fallback per-user)  |
//! | `general` | `desync_all_full`              | Applied immediately                            |
//! | `general` | `update_every`                 | Applied to ME updater immediately              |
//! | `general` | `me_reinit_*`                  | Applied to ME reinit scheduler immediately     |
//! | `general` | `hardswap` / `me_*_reinit`     | Applied on next ME map update                  |
//! | `general` | `telemetry` / `me_*_policy`    | Applied immediately                            |
//! | `network` | `dns_overrides`                | Applied immediately                            |
//! | `access`  | All user/quota fields          | Effective immediately                          |
//!
//! Fields that require re-binding sockets (`server.port`, `censorship.*`,
//! `network.*`, `use_middle_proxy`) are **not** applied; a warning is emitted.
//! Non-hot changes are never mixed into the runtime config snapshot.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use crate::config::{
    LogLevel, MeBindStaleMode, MeFloorMode, MeSocksKdfPolicy, MeTelemetryLevel,
    MeWriterPickMode,
};
use super::load::{LoadedConfig, ProxyConfig};

const HOT_RELOAD_DEBOUNCE: Duration = Duration::from_millis(50);

// ── Hot fields ────────────────────────────────────────────────────────────────

/// Fields that are safe to swap without restarting listeners.
#[derive(Debug, Clone, PartialEq)]
pub struct HotFields {
    pub log_level:               LogLevel,
    pub ad_tag:                  Option<String>,
    pub dns_overrides:           Vec<String>,
    pub desync_all_full:         bool,
    pub update_every_secs:       u64,
    pub me_reinit_every_secs:    u64,
    pub me_reinit_singleflight:  bool,
    pub me_reinit_coalesce_window_ms: u64,
    pub hardswap:                bool,
    pub me_pool_drain_ttl_secs:  u64,
    pub me_instadrain: bool,
    pub me_pool_drain_threshold: u64,
    pub me_pool_min_fresh_ratio: f32,
    pub me_reinit_drain_timeout_secs: u64,
    pub me_hardswap_warmup_delay_min_ms: u64,
    pub me_hardswap_warmup_delay_max_ms: u64,
    pub me_hardswap_warmup_extra_passes: u8,
    pub me_hardswap_warmup_pass_backoff_base_ms: u64,
    pub me_bind_stale_mode: MeBindStaleMode,
    pub me_bind_stale_ttl_secs: u64,
    pub me_secret_atomic_snapshot: bool,
    pub me_deterministic_writer_sort: bool,
    pub me_writer_pick_mode: MeWriterPickMode,
    pub me_writer_pick_sample_size: u8,
    pub me_single_endpoint_shadow_writers: u8,
    pub me_single_endpoint_outage_mode_enabled: bool,
    pub me_single_endpoint_outage_disable_quarantine: bool,
    pub me_single_endpoint_outage_backoff_min_ms: u64,
    pub me_single_endpoint_outage_backoff_max_ms: u64,
    pub me_single_endpoint_shadow_rotate_every_secs: u64,
    pub me_config_stable_snapshots: u8,
    pub me_config_apply_cooldown_secs: u64,
    pub me_snapshot_require_http_2xx: bool,
    pub me_snapshot_reject_empty_map: bool,
    pub me_snapshot_min_proxy_for_lines: u32,
    pub proxy_secret_stable_snapshots: u8,
    pub proxy_secret_rotate_runtime: bool,
    pub proxy_secret_len_max: usize,
    pub telemetry_core_enabled: bool,
    pub telemetry_user_enabled: bool,
    pub telemetry_me_level: MeTelemetryLevel,
    pub me_socks_kdf_policy: MeSocksKdfPolicy,
    pub me_floor_mode: MeFloorMode,
    pub me_adaptive_floor_idle_secs: u64,
    pub me_adaptive_floor_min_writers_single_endpoint: u8,
    pub me_adaptive_floor_min_writers_multi_endpoint: u8,
    pub me_adaptive_floor_recover_grace_secs: u64,
    pub me_adaptive_floor_writers_per_core_total: u16,
    pub me_adaptive_floor_cpu_cores_override: u16,
    pub me_adaptive_floor_max_extra_writers_single_per_core: u16,
    pub me_adaptive_floor_max_extra_writers_multi_per_core: u16,
    pub me_adaptive_floor_max_active_writers_per_core: u16,
    pub me_adaptive_floor_max_warm_writers_per_core: u16,
    pub me_adaptive_floor_max_active_writers_global: u32,
    pub me_adaptive_floor_max_warm_writers_global: u32,
    pub me_route_backpressure_base_timeout_ms: u64,
    pub me_route_backpressure_high_timeout_ms: u64,
    pub me_route_backpressure_high_watermark_pct: u8,
    pub me_reader_route_data_wait_ms: u64,
    pub me_d2c_flush_batch_max_frames: usize,
    pub me_d2c_flush_batch_max_bytes: usize,
    pub me_d2c_flush_batch_max_delay_us: u64,
    pub me_d2c_ack_flush_immediate: bool,
    pub direct_relay_copy_buf_c2s_bytes: usize,
    pub direct_relay_copy_buf_s2c_bytes: usize,
    pub me_health_interval_ms_unhealthy: u64,
    pub me_health_interval_ms_healthy: u64,
    pub me_admission_poll_ms: u64,
    pub me_warn_rate_limit_ms: u64,
    pub users:                   std::collections::HashMap<String, String>,
    pub user_ad_tags:            std::collections::HashMap<String, String>,
    pub user_max_tcp_conns:      std::collections::HashMap<String, usize>,
    pub user_expirations:        std::collections::HashMap<String, chrono::DateTime<chrono::Utc>>,
    pub user_data_quota:         std::collections::HashMap<String, u64>,
    pub user_max_unique_ips:     std::collections::HashMap<String, usize>,
    pub user_max_unique_ips_global_each: usize,
    pub user_max_unique_ips_mode: crate::config::UserMaxUniqueIpsMode,
    pub user_max_unique_ips_window_secs: u64,
}

impl HotFields {
    pub fn from_config(cfg: &ProxyConfig) -> Self {
        Self {
            log_level:               cfg.general.log_level.clone(),
            ad_tag:                  cfg.general.ad_tag.clone(),
            dns_overrides:           cfg.network.dns_overrides.clone(),
            desync_all_full:         cfg.general.desync_all_full,
            update_every_secs:       cfg.general.effective_update_every_secs(),
            me_reinit_every_secs:    cfg.general.me_reinit_every_secs,
            me_reinit_singleflight:  cfg.general.me_reinit_singleflight,
            me_reinit_coalesce_window_ms: cfg.general.me_reinit_coalesce_window_ms,
            hardswap:                cfg.general.hardswap,
            me_pool_drain_ttl_secs:  cfg.general.me_pool_drain_ttl_secs,
            me_instadrain: cfg.general.me_instadrain,
            me_pool_drain_threshold: cfg.general.me_pool_drain_threshold,
            me_pool_min_fresh_ratio: cfg.general.me_pool_min_fresh_ratio,
            me_reinit_drain_timeout_secs: cfg.general.me_reinit_drain_timeout_secs,
            me_hardswap_warmup_delay_min_ms: cfg.general.me_hardswap_warmup_delay_min_ms,
            me_hardswap_warmup_delay_max_ms: cfg.general.me_hardswap_warmup_delay_max_ms,
            me_hardswap_warmup_extra_passes: cfg.general.me_hardswap_warmup_extra_passes,
            me_hardswap_warmup_pass_backoff_base_ms: cfg
                .general
                .me_hardswap_warmup_pass_backoff_base_ms,
            me_bind_stale_mode: cfg.general.me_bind_stale_mode,
            me_bind_stale_ttl_secs: cfg.general.me_bind_stale_ttl_secs,
            me_secret_atomic_snapshot: cfg.general.me_secret_atomic_snapshot,
            me_deterministic_writer_sort: cfg.general.me_deterministic_writer_sort,
            me_writer_pick_mode: cfg.general.me_writer_pick_mode,
            me_writer_pick_sample_size: cfg.general.me_writer_pick_sample_size,
            me_single_endpoint_shadow_writers: cfg.general.me_single_endpoint_shadow_writers,
            me_single_endpoint_outage_mode_enabled: cfg
                .general
                .me_single_endpoint_outage_mode_enabled,
            me_single_endpoint_outage_disable_quarantine: cfg
                .general
                .me_single_endpoint_outage_disable_quarantine,
            me_single_endpoint_outage_backoff_min_ms: cfg
                .general
                .me_single_endpoint_outage_backoff_min_ms,
            me_single_endpoint_outage_backoff_max_ms: cfg
                .general
                .me_single_endpoint_outage_backoff_max_ms,
            me_single_endpoint_shadow_rotate_every_secs: cfg
                .general
                .me_single_endpoint_shadow_rotate_every_secs,
            me_config_stable_snapshots: cfg.general.me_config_stable_snapshots,
            me_config_apply_cooldown_secs: cfg.general.me_config_apply_cooldown_secs,
            me_snapshot_require_http_2xx: cfg.general.me_snapshot_require_http_2xx,
            me_snapshot_reject_empty_map: cfg.general.me_snapshot_reject_empty_map,
            me_snapshot_min_proxy_for_lines: cfg.general.me_snapshot_min_proxy_for_lines,
            proxy_secret_stable_snapshots: cfg.general.proxy_secret_stable_snapshots,
            proxy_secret_rotate_runtime: cfg.general.proxy_secret_rotate_runtime,
            proxy_secret_len_max: cfg.general.proxy_secret_len_max,
            telemetry_core_enabled: cfg.general.telemetry.core_enabled,
            telemetry_user_enabled: cfg.general.telemetry.user_enabled,
            telemetry_me_level: cfg.general.telemetry.me_level,
            me_socks_kdf_policy: cfg.general.me_socks_kdf_policy,
            me_floor_mode: cfg.general.me_floor_mode,
            me_adaptive_floor_idle_secs: cfg.general.me_adaptive_floor_idle_secs,
            me_adaptive_floor_min_writers_single_endpoint: cfg
                .general
                .me_adaptive_floor_min_writers_single_endpoint,
            me_adaptive_floor_min_writers_multi_endpoint: cfg
                .general
                .me_adaptive_floor_min_writers_multi_endpoint,
            me_adaptive_floor_recover_grace_secs: cfg
                .general
                .me_adaptive_floor_recover_grace_secs,
            me_adaptive_floor_writers_per_core_total: cfg
                .general
                .me_adaptive_floor_writers_per_core_total,
            me_adaptive_floor_cpu_cores_override: cfg
                .general
                .me_adaptive_floor_cpu_cores_override,
            me_adaptive_floor_max_extra_writers_single_per_core: cfg
                .general
                .me_adaptive_floor_max_extra_writers_single_per_core,
            me_adaptive_floor_max_extra_writers_multi_per_core: cfg
                .general
                .me_adaptive_floor_max_extra_writers_multi_per_core,
            me_adaptive_floor_max_active_writers_per_core: cfg
                .general
                .me_adaptive_floor_max_active_writers_per_core,
            me_adaptive_floor_max_warm_writers_per_core: cfg
                .general
                .me_adaptive_floor_max_warm_writers_per_core,
            me_adaptive_floor_max_active_writers_global: cfg
                .general
                .me_adaptive_floor_max_active_writers_global,
            me_adaptive_floor_max_warm_writers_global: cfg
                .general
                .me_adaptive_floor_max_warm_writers_global,
            me_route_backpressure_base_timeout_ms: cfg.general.me_route_backpressure_base_timeout_ms,
            me_route_backpressure_high_timeout_ms: cfg.general.me_route_backpressure_high_timeout_ms,
            me_route_backpressure_high_watermark_pct: cfg.general.me_route_backpressure_high_watermark_pct,
            me_reader_route_data_wait_ms: cfg.general.me_reader_route_data_wait_ms,
            me_d2c_flush_batch_max_frames: cfg.general.me_d2c_flush_batch_max_frames,
            me_d2c_flush_batch_max_bytes: cfg.general.me_d2c_flush_batch_max_bytes,
            me_d2c_flush_batch_max_delay_us: cfg.general.me_d2c_flush_batch_max_delay_us,
            me_d2c_ack_flush_immediate: cfg.general.me_d2c_ack_flush_immediate,
            direct_relay_copy_buf_c2s_bytes: cfg.general.direct_relay_copy_buf_c2s_bytes,
            direct_relay_copy_buf_s2c_bytes: cfg.general.direct_relay_copy_buf_s2c_bytes,
            me_health_interval_ms_unhealthy: cfg.general.me_health_interval_ms_unhealthy,
            me_health_interval_ms_healthy: cfg.general.me_health_interval_ms_healthy,
            me_admission_poll_ms: cfg.general.me_admission_poll_ms,
            me_warn_rate_limit_ms: cfg.general.me_warn_rate_limit_ms,
            users:                   cfg.access.users.clone(),
            user_ad_tags:            cfg.access.user_ad_tags.clone(),
            user_max_tcp_conns:      cfg.access.user_max_tcp_conns.clone(),
            user_expirations:        cfg.access.user_expirations.clone(),
            user_data_quota:         cfg.access.user_data_quota.clone(),
            user_max_unique_ips:     cfg.access.user_max_unique_ips.clone(),
            user_max_unique_ips_global_each: cfg.access.user_max_unique_ips_global_each,
            user_max_unique_ips_mode: cfg.access.user_max_unique_ips_mode,
            user_max_unique_ips_window_secs: cfg.access.user_max_unique_ips_window_secs,
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn canonicalize_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            let mut pairs: Vec<(String, serde_json::Value)> =
                std::mem::take(map).into_iter().collect();
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, item) in pairs.iter_mut() {
                canonicalize_json(item);
            }
            for (key, item) in pairs {
                map.insert(key, item);
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                canonicalize_json(item);
            }
        }
        _ => {}
    }
}

fn config_equal(lhs: &ProxyConfig, rhs: &ProxyConfig) -> bool {
    let mut left = match serde_json::to_value(lhs) {
        Ok(value) => value,
        Err(_) => return false,
    };
    let mut right = match serde_json::to_value(rhs) {
        Ok(value) => value,
        Err(_) => return false,
    };
    canonicalize_json(&mut left);
    canonicalize_json(&mut right);
    left == right
}

fn listeners_equal(
    lhs: &[crate::config::ListenerConfig],
    rhs: &[crate::config::ListenerConfig],
) -> bool {
    if lhs.len() != rhs.len() {
        return false;
    }
    lhs.iter().zip(rhs.iter()).all(|(a, b)| {
        a.ip == b.ip
            && a.announce == b.announce
            && a.announce_ip == b.announce_ip
            && a.proxy_protocol == b.proxy_protocol
            && a.reuse_allow == b.reuse_allow
    })
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WatchManifest {
    files: BTreeSet<PathBuf>,
    dirs: BTreeSet<PathBuf>,
}

impl WatchManifest {
    fn from_source_files(source_files: &[PathBuf]) -> Self {
        let mut files = BTreeSet::new();
        let mut dirs = BTreeSet::new();

        for path in source_files {
            let normalized = normalize_watch_path(path);
            files.insert(normalized.clone());
            if let Some(parent) = normalized.parent() {
                dirs.insert(parent.to_path_buf());
            }
        }

        Self { files, dirs }
    }

    fn matches_event_paths(&self, event_paths: &[PathBuf]) -> bool {
        event_paths
            .iter()
            .map(|path| normalize_watch_path(path))
            .any(|path| self.files.contains(&path))
    }
}

#[derive(Debug, Default)]
struct ReloadState {
    applied_snapshot_hash: Option<u64>,
}

impl ReloadState {
    fn new(applied_snapshot_hash: Option<u64>) -> Self {
        Self { applied_snapshot_hash }
    }

    fn is_applied(&self, hash: u64) -> bool {
        self.applied_snapshot_hash == Some(hash)
    }

    fn mark_applied(&mut self, hash: u64) {
        self.applied_snapshot_hash = Some(hash);
    }
}

fn normalize_watch_path(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|cwd| cwd.join(path))
                .unwrap_or_else(|_| path.to_path_buf())
        }
    })
}

fn sync_watch_paths<W: Watcher>(
    watcher: &mut W,
    current: &BTreeSet<PathBuf>,
    next: &BTreeSet<PathBuf>,
    recursive_mode: RecursiveMode,
    kind: &str,
) {
    for path in current.difference(next) {
        if let Err(e) = watcher.unwatch(path) {
            warn!(path = %path.display(), error = %e, "config watcher: failed to unwatch {kind}");
        }
    }

    for path in next.difference(current) {
        if let Err(e) = watcher.watch(path, recursive_mode) {
            warn!(path = %path.display(), error = %e, "config watcher: failed to watch {kind}");
        }
    }
}

fn apply_watch_manifest<W1: Watcher, W2: Watcher>(
    notify_watcher: Option<&mut W1>,
    poll_watcher: Option<&mut W2>,
    manifest_state: &Arc<StdRwLock<WatchManifest>>,
    next_manifest: WatchManifest,
) {
    let current_manifest = manifest_state
        .read()
        .map(|manifest| manifest.clone())
        .unwrap_or_default();

    if current_manifest == next_manifest {
        return;
    }

    if let Some(watcher) = notify_watcher {
        sync_watch_paths(
            watcher,
            &current_manifest.dirs,
            &next_manifest.dirs,
            RecursiveMode::NonRecursive,
            "config directory",
        );
    }

    if let Some(watcher) = poll_watcher {
        sync_watch_paths(
            watcher,
            &current_manifest.files,
            &next_manifest.files,
            RecursiveMode::NonRecursive,
            "config file",
        );
    }

    if let Ok(mut manifest) = manifest_state.write() {
        *manifest = next_manifest;
    }
}

fn overlay_hot_fields(old: &ProxyConfig, new: &ProxyConfig) -> ProxyConfig {
    let mut cfg = old.clone();

    cfg.general.log_level = new.general.log_level.clone();
    cfg.general.ad_tag = new.general.ad_tag.clone();
    cfg.network.dns_overrides = new.network.dns_overrides.clone();
    cfg.general.desync_all_full = new.general.desync_all_full;
    cfg.general.update_every = new.general.update_every;
    cfg.general.proxy_secret_auto_reload_secs = new.general.proxy_secret_auto_reload_secs;
    cfg.general.proxy_config_auto_reload_secs = new.general.proxy_config_auto_reload_secs;
    cfg.general.me_reinit_every_secs = new.general.me_reinit_every_secs;
    cfg.general.me_reinit_singleflight = new.general.me_reinit_singleflight;
    cfg.general.me_reinit_coalesce_window_ms = new.general.me_reinit_coalesce_window_ms;
    cfg.general.hardswap = new.general.hardswap;
    cfg.general.me_pool_drain_ttl_secs = new.general.me_pool_drain_ttl_secs;
    cfg.general.me_instadrain = new.general.me_instadrain;
    cfg.general.me_pool_drain_threshold = new.general.me_pool_drain_threshold;
    cfg.general.me_pool_min_fresh_ratio = new.general.me_pool_min_fresh_ratio;
    cfg.general.me_reinit_drain_timeout_secs = new.general.me_reinit_drain_timeout_secs;
    cfg.general.me_hardswap_warmup_delay_min_ms = new.general.me_hardswap_warmup_delay_min_ms;
    cfg.general.me_hardswap_warmup_delay_max_ms = new.general.me_hardswap_warmup_delay_max_ms;
    cfg.general.me_hardswap_warmup_extra_passes = new.general.me_hardswap_warmup_extra_passes;
    cfg.general.me_hardswap_warmup_pass_backoff_base_ms =
        new.general.me_hardswap_warmup_pass_backoff_base_ms;
    cfg.general.me_bind_stale_mode = new.general.me_bind_stale_mode;
    cfg.general.me_bind_stale_ttl_secs = new.general.me_bind_stale_ttl_secs;
    cfg.general.me_secret_atomic_snapshot = new.general.me_secret_atomic_snapshot;
    cfg.general.me_deterministic_writer_sort = new.general.me_deterministic_writer_sort;
    cfg.general.me_writer_pick_mode = new.general.me_writer_pick_mode;
    cfg.general.me_writer_pick_sample_size = new.general.me_writer_pick_sample_size;
    cfg.general.me_single_endpoint_shadow_writers = new.general.me_single_endpoint_shadow_writers;
    cfg.general.me_single_endpoint_outage_mode_enabled =
        new.general.me_single_endpoint_outage_mode_enabled;
    cfg.general.me_single_endpoint_outage_disable_quarantine =
        new.general.me_single_endpoint_outage_disable_quarantine;
    cfg.general.me_single_endpoint_outage_backoff_min_ms =
        new.general.me_single_endpoint_outage_backoff_min_ms;
    cfg.general.me_single_endpoint_outage_backoff_max_ms =
        new.general.me_single_endpoint_outage_backoff_max_ms;
    cfg.general.me_single_endpoint_shadow_rotate_every_secs =
        new.general.me_single_endpoint_shadow_rotate_every_secs;
    cfg.general.me_config_stable_snapshots = new.general.me_config_stable_snapshots;
    cfg.general.me_config_apply_cooldown_secs = new.general.me_config_apply_cooldown_secs;
    cfg.general.me_snapshot_require_http_2xx = new.general.me_snapshot_require_http_2xx;
    cfg.general.me_snapshot_reject_empty_map = new.general.me_snapshot_reject_empty_map;
    cfg.general.me_snapshot_min_proxy_for_lines = new.general.me_snapshot_min_proxy_for_lines;
    cfg.general.proxy_secret_stable_snapshots = new.general.proxy_secret_stable_snapshots;
    cfg.general.proxy_secret_rotate_runtime = new.general.proxy_secret_rotate_runtime;
    cfg.general.proxy_secret_len_max = new.general.proxy_secret_len_max;
    cfg.general.telemetry = new.general.telemetry.clone();
    cfg.general.me_socks_kdf_policy = new.general.me_socks_kdf_policy;
    cfg.general.me_floor_mode = new.general.me_floor_mode;
    cfg.general.me_adaptive_floor_idle_secs = new.general.me_adaptive_floor_idle_secs;
    cfg.general.me_adaptive_floor_min_writers_single_endpoint =
        new.general.me_adaptive_floor_min_writers_single_endpoint;
    cfg.general.me_adaptive_floor_min_writers_multi_endpoint =
        new.general.me_adaptive_floor_min_writers_multi_endpoint;
    cfg.general.me_adaptive_floor_recover_grace_secs =
        new.general.me_adaptive_floor_recover_grace_secs;
    cfg.general.me_adaptive_floor_writers_per_core_total =
        new.general.me_adaptive_floor_writers_per_core_total;
    cfg.general.me_adaptive_floor_cpu_cores_override =
        new.general.me_adaptive_floor_cpu_cores_override;
    cfg.general.me_adaptive_floor_max_extra_writers_single_per_core =
        new.general.me_adaptive_floor_max_extra_writers_single_per_core;
    cfg.general.me_adaptive_floor_max_extra_writers_multi_per_core =
        new.general.me_adaptive_floor_max_extra_writers_multi_per_core;
    cfg.general.me_adaptive_floor_max_active_writers_per_core =
        new.general.me_adaptive_floor_max_active_writers_per_core;
    cfg.general.me_adaptive_floor_max_warm_writers_per_core =
        new.general.me_adaptive_floor_max_warm_writers_per_core;
    cfg.general.me_adaptive_floor_max_active_writers_global =
        new.general.me_adaptive_floor_max_active_writers_global;
    cfg.general.me_adaptive_floor_max_warm_writers_global =
        new.general.me_adaptive_floor_max_warm_writers_global;
    cfg.general.me_route_backpressure_base_timeout_ms =
        new.general.me_route_backpressure_base_timeout_ms;
    cfg.general.me_route_backpressure_high_timeout_ms =
        new.general.me_route_backpressure_high_timeout_ms;
    cfg.general.me_route_backpressure_high_watermark_pct =
        new.general.me_route_backpressure_high_watermark_pct;
    cfg.general.me_reader_route_data_wait_ms = new.general.me_reader_route_data_wait_ms;
    cfg.general.me_d2c_flush_batch_max_frames = new.general.me_d2c_flush_batch_max_frames;
    cfg.general.me_d2c_flush_batch_max_bytes = new.general.me_d2c_flush_batch_max_bytes;
    cfg.general.me_d2c_flush_batch_max_delay_us = new.general.me_d2c_flush_batch_max_delay_us;
    cfg.general.me_d2c_ack_flush_immediate = new.general.me_d2c_ack_flush_immediate;
    cfg.general.direct_relay_copy_buf_c2s_bytes = new.general.direct_relay_copy_buf_c2s_bytes;
    cfg.general.direct_relay_copy_buf_s2c_bytes = new.general.direct_relay_copy_buf_s2c_bytes;
    cfg.general.me_health_interval_ms_unhealthy = new.general.me_health_interval_ms_unhealthy;
    cfg.general.me_health_interval_ms_healthy = new.general.me_health_interval_ms_healthy;
    cfg.general.me_admission_poll_ms = new.general.me_admission_poll_ms;
    cfg.general.me_warn_rate_limit_ms = new.general.me_warn_rate_limit_ms;

    cfg.access.users = new.access.users.clone();
    cfg.access.user_ad_tags = new.access.user_ad_tags.clone();
    cfg.access.user_max_tcp_conns = new.access.user_max_tcp_conns.clone();
    cfg.access.user_expirations = new.access.user_expirations.clone();
    cfg.access.user_data_quota = new.access.user_data_quota.clone();
    cfg.access.user_max_unique_ips = new.access.user_max_unique_ips.clone();
    cfg.access.user_max_unique_ips_global_each = new.access.user_max_unique_ips_global_each;
    cfg.access.user_max_unique_ips_mode = new.access.user_max_unique_ips_mode;
    cfg.access.user_max_unique_ips_window_secs = new.access.user_max_unique_ips_window_secs;

    cfg
}

/// Warn if any non-hot fields changed (require restart).
fn warn_non_hot_changes(old: &ProxyConfig, new: &ProxyConfig, non_hot_changed: bool) {
    let mut warned = false;
    if old.server.port != new.server.port {
        warned = true;
        warn!(
            "config reload: server.port changed ({} → {}); restart required",
            old.server.port, new.server.port
        );
    }
    if old.server.api.enabled != new.server.api.enabled
        || old.server.api.listen != new.server.api.listen
        || old.server.api.whitelist != new.server.api.whitelist
        || old.server.api.auth_header != new.server.api.auth_header
        || old.server.api.request_body_limit_bytes != new.server.api.request_body_limit_bytes
        || old.server.api.minimal_runtime_enabled != new.server.api.minimal_runtime_enabled
        || old.server.api.minimal_runtime_cache_ttl_ms
            != new.server.api.minimal_runtime_cache_ttl_ms
        || old.server.api.runtime_edge_enabled != new.server.api.runtime_edge_enabled
        || old.server.api.runtime_edge_cache_ttl_ms
            != new.server.api.runtime_edge_cache_ttl_ms
        || old.server.api.runtime_edge_top_n != new.server.api.runtime_edge_top_n
        || old.server.api.runtime_edge_events_capacity
            != new.server.api.runtime_edge_events_capacity
        || old.server.api.read_only != new.server.api.read_only
    {
        warned = true;
        warn!("config reload: server.api changed; restart required");
    }
    if old.server.proxy_protocol != new.server.proxy_protocol
        || !listeners_equal(&old.server.listeners, &new.server.listeners)
        || old.server.listen_addr_ipv4 != new.server.listen_addr_ipv4
        || old.server.listen_addr_ipv6 != new.server.listen_addr_ipv6
        || old.server.listen_tcp != new.server.listen_tcp
        || old.server.listen_unix_sock != new.server.listen_unix_sock
        || old.server.listen_unix_sock_perm != new.server.listen_unix_sock_perm
    {
        warned = true;
        warn!("config reload: server listener settings changed; restart required");
    }
    if old.censorship.tls_domain != new.censorship.tls_domain
        || old.censorship.tls_domains != new.censorship.tls_domains
        || old.censorship.tls_fetch_scope != new.censorship.tls_fetch_scope
        || old.censorship.mask != new.censorship.mask
        || old.censorship.mask_host != new.censorship.mask_host
        || old.censorship.mask_port != new.censorship.mask_port
        || old.censorship.mask_unix_sock != new.censorship.mask_unix_sock
        || old.censorship.fake_cert_len != new.censorship.fake_cert_len
        || old.censorship.tls_emulation != new.censorship.tls_emulation
        || old.censorship.tls_front_dir != new.censorship.tls_front_dir
        || old.censorship.server_hello_delay_min_ms != new.censorship.server_hello_delay_min_ms
        || old.censorship.server_hello_delay_max_ms != new.censorship.server_hello_delay_max_ms
        || old.censorship.tls_new_session_tickets != new.censorship.tls_new_session_tickets
        || old.censorship.tls_full_cert_ttl_secs != new.censorship.tls_full_cert_ttl_secs
        || old.censorship.alpn_enforce != new.censorship.alpn_enforce
        || old.censorship.mask_proxy_protocol != new.censorship.mask_proxy_protocol
        || old.censorship.mask_shape_hardening != new.censorship.mask_shape_hardening
        || old.censorship.mask_shape_bucket_floor_bytes
            != new.censorship.mask_shape_bucket_floor_bytes
        || old.censorship.mask_shape_bucket_cap_bytes
            != new.censorship.mask_shape_bucket_cap_bytes
        || old.censorship.mask_shape_above_cap_blur
            != new.censorship.mask_shape_above_cap_blur
        || old.censorship.mask_shape_above_cap_blur_max_bytes
            != new.censorship.mask_shape_above_cap_blur_max_bytes
        || old.censorship.mask_timing_normalization_enabled
            != new.censorship.mask_timing_normalization_enabled
        || old.censorship.mask_timing_normalization_floor_ms
            != new.censorship.mask_timing_normalization_floor_ms
        || old.censorship.mask_timing_normalization_ceiling_ms
            != new.censorship.mask_timing_normalization_ceiling_ms
    {
        warned = true;
        warn!("config reload: censorship settings changed; restart required");
    }
    if old.censorship.tls_domain != new.censorship.tls_domain {
        warned = true;
        warn!(
            "config reload: censorship.tls_domain changed ('{}' → '{}'); restart required",
            old.censorship.tls_domain, new.censorship.tls_domain
        );
    }
    if old.network.ipv4 != new.network.ipv4 || old.network.ipv6 != new.network.ipv6 {
        warned = true;
        warn!("config reload: network.ipv4/ipv6 changed; restart required");
    }
    if old.network.prefer != new.network.prefer
        || old.network.multipath != new.network.multipath
        || old.network.stun_use != new.network.stun_use
        || old.network.stun_servers != new.network.stun_servers
        || old.network.stun_tcp_fallback != new.network.stun_tcp_fallback
        || old.network.http_ip_detect_urls != new.network.http_ip_detect_urls
        || old.network.cache_public_ip_path != new.network.cache_public_ip_path
    {
        warned = true;
        warn!("config reload: non-hot network settings changed; restart required");
    }
    if old.general.use_middle_proxy != new.general.use_middle_proxy {
        warned = true;
        warn!("config reload: use_middle_proxy changed; restart required");
    }
    if old.general.stun_nat_probe_concurrency != new.general.stun_nat_probe_concurrency {
        warned = true;
        warn!("config reload: general.stun_nat_probe_concurrency changed; restart required");
    }
    if old.general.middle_proxy_pool_size != new.general.middle_proxy_pool_size {
        warned = true;
        warn!("config reload: general.middle_proxy_pool_size changed; restart required");
    }
    if old.general.me_route_no_writer_mode != new.general.me_route_no_writer_mode
        || old.general.me_route_no_writer_wait_ms != new.general.me_route_no_writer_wait_ms
        || old.general.me_route_inline_recovery_attempts
            != new.general.me_route_inline_recovery_attempts
        || old.general.me_route_inline_recovery_wait_ms
            != new.general.me_route_inline_recovery_wait_ms
    {
        warned = true;
        warn!("config reload: general.me_route_no_writer_* changed; restart required");
    }
    if old.general.unknown_dc_log_path != new.general.unknown_dc_log_path
        || old.general.unknown_dc_file_log_enabled != new.general.unknown_dc_file_log_enabled
    {
        warned = true;
        warn!("config reload: general.unknown_dc_* changed; restart required");
    }
    if old.general.me_init_retry_attempts != new.general.me_init_retry_attempts {
        warned = true;
        warn!("config reload: general.me_init_retry_attempts changed; restart required");
    }
    if old.general.me2dc_fallback != new.general.me2dc_fallback {
        warned = true;
        warn!("config reload: general.me2dc_fallback changed; restart required");
    }
    if old.general.proxy_config_v4_cache_path != new.general.proxy_config_v4_cache_path
        || old.general.proxy_config_v6_cache_path != new.general.proxy_config_v6_cache_path
    {
        warned = true;
        warn!("config reload: general.proxy_config_*_cache_path changed; restart required");
    }
    if old.general.me_keepalive_enabled != new.general.me_keepalive_enabled
        || old.general.me_keepalive_interval_secs != new.general.me_keepalive_interval_secs
        || old.general.me_keepalive_jitter_secs != new.general.me_keepalive_jitter_secs
        || old.general.me_keepalive_payload_random != new.general.me_keepalive_payload_random
    {
        warned = true;
        warn!("config reload: general.me_keepalive_* changed; restart required");
    }
    if old.general.upstream_connect_retry_attempts != new.general.upstream_connect_retry_attempts
        || old.general.upstream_connect_retry_backoff_ms
            != new.general.upstream_connect_retry_backoff_ms
        || old.general.upstream_unhealthy_fail_threshold
            != new.general.upstream_unhealthy_fail_threshold
        || old.general.upstream_connect_failfast_hard_errors
            != new.general.upstream_connect_failfast_hard_errors
        || old.general.rpc_proxy_req_every != new.general.rpc_proxy_req_every
    {
        warned = true;
        warn!("config reload: general.upstream_* changed; restart required");
    }
    if non_hot_changed && !warned {
        warn!("config reload: one or more non-hot fields changed; restart required");
    }
}

/// Resolve the public host for link generation — mirrors the logic in main.rs.
///
/// Priority:
/// 1. `[general.links] public_host` — explicit override in config
/// 2. `detected_ip_v4` — from STUN/interface probe at startup
/// 3. `detected_ip_v6` — fallback
/// 4. `"UNKNOWN"` — warn the user to set `public_host`
fn resolve_link_host(
    cfg: &ProxyConfig,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) -> String {
    if let Some(ref h) = cfg.general.links.public_host {
        return h.clone();
    }
    detected_ip_v4
        .or(detected_ip_v6)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| {
            warn!(
                "config reload: could not determine public IP for proxy links. \
                 Set [general.links] public_host in config."
            );
            "UNKNOWN".to_string()
        })
}

/// Print TG proxy links for a single user — mirrors print_proxy_links() in main.rs.
fn print_user_links(user: &str, secret: &str, host: &str, port: u16, cfg: &ProxyConfig) {
    info!(target: "telemt::links", "--- New user: {} ---", user);
    if cfg.general.modes.classic {
        info!(
            target: "telemt::links",
            "  Classic: tg://proxy?server={}&port={}&secret={}",
            host, port, secret
        );
    }
    if cfg.general.modes.secure {
        info!(
            target: "telemt::links",
            "  DD:      tg://proxy?server={}&port={}&secret=dd{}",
            host, port, secret
        );
    }
    if cfg.general.modes.tls {
        let mut domains = vec![cfg.censorship.tls_domain.clone()];
        for d in &cfg.censorship.tls_domains {
            if !domains.contains(d) {
                domains.push(d.clone());
            }
        }
        for domain in &domains {
            let domain_hex = hex::encode(domain.as_bytes());
            info!(
                target: "telemt::links",
                "  EE-TLS:  tg://proxy?server={}&port={}&secret=ee{}{}",
                host, port, secret, domain_hex
            );
        }
    }
    info!(target: "telemt::links", "--------------------");
}

/// Log all detected changes and emit TG links for new users.
fn log_changes(
    old_hot: &HotFields,
    new_hot: &HotFields,
    new_cfg: &ProxyConfig,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) {
    if old_hot.log_level != new_hot.log_level {
        info!(
            "config reload: log_level: '{}' → '{}'",
            old_hot.log_level, new_hot.log_level
        );
        log_tx.send(new_hot.log_level.clone()).ok();
    }

    if old_hot.user_ad_tags != new_hot.user_ad_tags {
        info!(
            "config reload: user_ad_tags updated ({} entries)",
            new_hot.user_ad_tags.len(),
        );
    }

    if old_hot.ad_tag != new_hot.ad_tag {
        info!("config reload: general.ad_tag updated (applied on next connection)");
    }

    if old_hot.dns_overrides != new_hot.dns_overrides {
        info!(
            "config reload: network.dns_overrides updated ({} entries)",
            new_hot.dns_overrides.len()
        );
    }

    if old_hot.desync_all_full != new_hot.desync_all_full {
        info!(
            "config reload: desync_all_full: {} → {}",
            old_hot.desync_all_full, new_hot.desync_all_full,
        );
    }

    if old_hot.update_every_secs != new_hot.update_every_secs {
        info!(
            "config reload: update_every(effective): {}s → {}s",
            old_hot.update_every_secs, new_hot.update_every_secs,
        );
    }
    if old_hot.me_reinit_every_secs != new_hot.me_reinit_every_secs
        || old_hot.me_reinit_singleflight != new_hot.me_reinit_singleflight
        || old_hot.me_reinit_coalesce_window_ms != new_hot.me_reinit_coalesce_window_ms
    {
        info!(
            "config reload: me_reinit: interval={}s singleflight={} coalesce={}ms",
            new_hot.me_reinit_every_secs,
            new_hot.me_reinit_singleflight,
            new_hot.me_reinit_coalesce_window_ms
        );
    }

    if old_hot.hardswap != new_hot.hardswap {
        info!(
            "config reload: hardswap: {} → {}",
            old_hot.hardswap, new_hot.hardswap,
        );
    }

    if old_hot.me_pool_drain_ttl_secs != new_hot.me_pool_drain_ttl_secs {
        info!(
            "config reload: me_pool_drain_ttl_secs: {}s → {}s",
            old_hot.me_pool_drain_ttl_secs, new_hot.me_pool_drain_ttl_secs,
        );
    }
    if old_hot.me_instadrain != new_hot.me_instadrain {
        info!(
            "config reload: me_instadrain: {} → {}",
            old_hot.me_instadrain, new_hot.me_instadrain,
        );
    }

    if old_hot.me_pool_drain_threshold != new_hot.me_pool_drain_threshold {
        info!(
            "config reload: me_pool_drain_threshold: {} → {}",
            old_hot.me_pool_drain_threshold, new_hot.me_pool_drain_threshold,
        );
    }

    if (old_hot.me_pool_min_fresh_ratio - new_hot.me_pool_min_fresh_ratio).abs() > f32::EPSILON {
        info!(
            "config reload: me_pool_min_fresh_ratio: {:.3} → {:.3}",
            old_hot.me_pool_min_fresh_ratio, new_hot.me_pool_min_fresh_ratio,
        );
    }

    if old_hot.me_reinit_drain_timeout_secs != new_hot.me_reinit_drain_timeout_secs {
        info!(
            "config reload: me_reinit_drain_timeout_secs: {}s → {}s",
            old_hot.me_reinit_drain_timeout_secs, new_hot.me_reinit_drain_timeout_secs,
        );
    }
    if old_hot.me_hardswap_warmup_delay_min_ms != new_hot.me_hardswap_warmup_delay_min_ms
        || old_hot.me_hardswap_warmup_delay_max_ms != new_hot.me_hardswap_warmup_delay_max_ms
        || old_hot.me_hardswap_warmup_extra_passes != new_hot.me_hardswap_warmup_extra_passes
        || old_hot.me_hardswap_warmup_pass_backoff_base_ms
            != new_hot.me_hardswap_warmup_pass_backoff_base_ms
    {
        info!(
            "config reload: me_hardswap_warmup: min={}ms max={}ms extra_passes={} pass_backoff={}ms",
            new_hot.me_hardswap_warmup_delay_min_ms,
            new_hot.me_hardswap_warmup_delay_max_ms,
            new_hot.me_hardswap_warmup_extra_passes,
            new_hot.me_hardswap_warmup_pass_backoff_base_ms
        );
    }
    if old_hot.me_bind_stale_mode != new_hot.me_bind_stale_mode
        || old_hot.me_bind_stale_ttl_secs != new_hot.me_bind_stale_ttl_secs
    {
        info!(
            "config reload: me_bind_stale: mode={:?} ttl={}s",
            new_hot.me_bind_stale_mode,
            new_hot.me_bind_stale_ttl_secs
        );
    }
    if old_hot.me_secret_atomic_snapshot != new_hot.me_secret_atomic_snapshot
        || old_hot.me_deterministic_writer_sort != new_hot.me_deterministic_writer_sort
        || old_hot.me_writer_pick_mode != new_hot.me_writer_pick_mode
        || old_hot.me_writer_pick_sample_size != new_hot.me_writer_pick_sample_size
    {
        info!(
            "config reload: me_runtime_flags: secret_atomic_snapshot={} deterministic_sort={} writer_pick_mode={:?} writer_pick_sample_size={}",
            new_hot.me_secret_atomic_snapshot,
            new_hot.me_deterministic_writer_sort,
            new_hot.me_writer_pick_mode,
            new_hot.me_writer_pick_sample_size,
        );
    }
    if old_hot.me_single_endpoint_shadow_writers != new_hot.me_single_endpoint_shadow_writers
        || old_hot.me_single_endpoint_outage_mode_enabled
            != new_hot.me_single_endpoint_outage_mode_enabled
        || old_hot.me_single_endpoint_outage_disable_quarantine
            != new_hot.me_single_endpoint_outage_disable_quarantine
        || old_hot.me_single_endpoint_outage_backoff_min_ms
            != new_hot.me_single_endpoint_outage_backoff_min_ms
        || old_hot.me_single_endpoint_outage_backoff_max_ms
            != new_hot.me_single_endpoint_outage_backoff_max_ms
        || old_hot.me_single_endpoint_shadow_rotate_every_secs
            != new_hot.me_single_endpoint_shadow_rotate_every_secs
    {
        info!(
            "config reload: me_single_endpoint: shadow={} outage_enabled={} disable_quarantine={} backoff=[{}..{}]ms rotate={}s",
            new_hot.me_single_endpoint_shadow_writers,
            new_hot.me_single_endpoint_outage_mode_enabled,
            new_hot.me_single_endpoint_outage_disable_quarantine,
            new_hot.me_single_endpoint_outage_backoff_min_ms,
            new_hot.me_single_endpoint_outage_backoff_max_ms,
            new_hot.me_single_endpoint_shadow_rotate_every_secs
        );
    }
    if old_hot.me_config_stable_snapshots != new_hot.me_config_stable_snapshots
        || old_hot.me_config_apply_cooldown_secs != new_hot.me_config_apply_cooldown_secs
        || old_hot.me_snapshot_require_http_2xx != new_hot.me_snapshot_require_http_2xx
        || old_hot.me_snapshot_reject_empty_map != new_hot.me_snapshot_reject_empty_map
        || old_hot.me_snapshot_min_proxy_for_lines != new_hot.me_snapshot_min_proxy_for_lines
    {
        info!(
            "config reload: me_snapshot_guard: stable={} cooldown={}s require_2xx={} reject_empty={} min_proxy_for={}",
            new_hot.me_config_stable_snapshots,
            new_hot.me_config_apply_cooldown_secs,
            new_hot.me_snapshot_require_http_2xx,
            new_hot.me_snapshot_reject_empty_map,
            new_hot.me_snapshot_min_proxy_for_lines
        );
    }
    if old_hot.proxy_secret_stable_snapshots != new_hot.proxy_secret_stable_snapshots
        || old_hot.proxy_secret_rotate_runtime != new_hot.proxy_secret_rotate_runtime
        || old_hot.proxy_secret_len_max != new_hot.proxy_secret_len_max
    {
        info!(
            "config reload: proxy_secret_runtime: stable={} rotate={} len_max={}",
            new_hot.proxy_secret_stable_snapshots,
            new_hot.proxy_secret_rotate_runtime,
            new_hot.proxy_secret_len_max
        );
    }

    if old_hot.telemetry_core_enabled != new_hot.telemetry_core_enabled
        || old_hot.telemetry_user_enabled != new_hot.telemetry_user_enabled
        || old_hot.telemetry_me_level != new_hot.telemetry_me_level
    {
        info!(
            "config reload: telemetry: core_enabled={} user_enabled={} me_level={}",
            new_hot.telemetry_core_enabled,
            new_hot.telemetry_user_enabled,
            new_hot.telemetry_me_level,
        );
    }

    if old_hot.me_socks_kdf_policy != new_hot.me_socks_kdf_policy {
        info!(
            "config reload: me_socks_kdf_policy: {:?} → {:?}",
            old_hot.me_socks_kdf_policy,
            new_hot.me_socks_kdf_policy,
        );
    }

    if old_hot.me_floor_mode != new_hot.me_floor_mode
        || old_hot.me_adaptive_floor_idle_secs != new_hot.me_adaptive_floor_idle_secs
        || old_hot.me_adaptive_floor_min_writers_single_endpoint
            != new_hot.me_adaptive_floor_min_writers_single_endpoint
        || old_hot.me_adaptive_floor_min_writers_multi_endpoint
            != new_hot.me_adaptive_floor_min_writers_multi_endpoint
        || old_hot.me_adaptive_floor_recover_grace_secs
            != new_hot.me_adaptive_floor_recover_grace_secs
        || old_hot.me_adaptive_floor_writers_per_core_total
            != new_hot.me_adaptive_floor_writers_per_core_total
        || old_hot.me_adaptive_floor_cpu_cores_override
            != new_hot.me_adaptive_floor_cpu_cores_override
        || old_hot.me_adaptive_floor_max_extra_writers_single_per_core
            != new_hot.me_adaptive_floor_max_extra_writers_single_per_core
        || old_hot.me_adaptive_floor_max_extra_writers_multi_per_core
            != new_hot.me_adaptive_floor_max_extra_writers_multi_per_core
        || old_hot.me_adaptive_floor_max_active_writers_per_core
            != new_hot.me_adaptive_floor_max_active_writers_per_core
        || old_hot.me_adaptive_floor_max_warm_writers_per_core
            != new_hot.me_adaptive_floor_max_warm_writers_per_core
        || old_hot.me_adaptive_floor_max_active_writers_global
            != new_hot.me_adaptive_floor_max_active_writers_global
        || old_hot.me_adaptive_floor_max_warm_writers_global
            != new_hot.me_adaptive_floor_max_warm_writers_global
    {
        info!(
            "config reload: me_floor: mode={:?} idle={}s min_single={} min_multi={} recover_grace={}s per_core_total={} cores_override={} extra_single_per_core={} extra_multi_per_core={} max_active_per_core={} max_warm_per_core={} max_active_global={} max_warm_global={}",
            new_hot.me_floor_mode,
            new_hot.me_adaptive_floor_idle_secs,
            new_hot.me_adaptive_floor_min_writers_single_endpoint,
            new_hot.me_adaptive_floor_min_writers_multi_endpoint,
            new_hot.me_adaptive_floor_recover_grace_secs,
            new_hot.me_adaptive_floor_writers_per_core_total,
            new_hot.me_adaptive_floor_cpu_cores_override,
            new_hot.me_adaptive_floor_max_extra_writers_single_per_core,
            new_hot.me_adaptive_floor_max_extra_writers_multi_per_core,
            new_hot.me_adaptive_floor_max_active_writers_per_core,
            new_hot.me_adaptive_floor_max_warm_writers_per_core,
            new_hot.me_adaptive_floor_max_active_writers_global,
            new_hot.me_adaptive_floor_max_warm_writers_global,
        );
    }

    if old_hot.me_route_backpressure_base_timeout_ms
        != new_hot.me_route_backpressure_base_timeout_ms
        || old_hot.me_route_backpressure_high_timeout_ms
            != new_hot.me_route_backpressure_high_timeout_ms
        || old_hot.me_route_backpressure_high_watermark_pct
            != new_hot.me_route_backpressure_high_watermark_pct
        || old_hot.me_reader_route_data_wait_ms != new_hot.me_reader_route_data_wait_ms
        || old_hot.me_health_interval_ms_unhealthy
            != new_hot.me_health_interval_ms_unhealthy
        || old_hot.me_health_interval_ms_healthy != new_hot.me_health_interval_ms_healthy
        || old_hot.me_admission_poll_ms != new_hot.me_admission_poll_ms
        || old_hot.me_warn_rate_limit_ms != new_hot.me_warn_rate_limit_ms
    {
        info!(
            "config reload: me_route_backpressure: base={}ms high={}ms watermark={}%; me_reader_route_data_wait_ms={}; me_health_interval: unhealthy={}ms healthy={}ms; me_admission_poll={}ms; me_warn_rate_limit={}ms",
            new_hot.me_route_backpressure_base_timeout_ms,
            new_hot.me_route_backpressure_high_timeout_ms,
            new_hot.me_route_backpressure_high_watermark_pct,
            new_hot.me_reader_route_data_wait_ms,
            new_hot.me_health_interval_ms_unhealthy,
            new_hot.me_health_interval_ms_healthy,
            new_hot.me_admission_poll_ms,
            new_hot.me_warn_rate_limit_ms,
        );
    }

    if old_hot.me_d2c_flush_batch_max_frames != new_hot.me_d2c_flush_batch_max_frames
        || old_hot.me_d2c_flush_batch_max_bytes != new_hot.me_d2c_flush_batch_max_bytes
        || old_hot.me_d2c_flush_batch_max_delay_us != new_hot.me_d2c_flush_batch_max_delay_us
        || old_hot.me_d2c_ack_flush_immediate != new_hot.me_d2c_ack_flush_immediate
        || old_hot.direct_relay_copy_buf_c2s_bytes != new_hot.direct_relay_copy_buf_c2s_bytes
        || old_hot.direct_relay_copy_buf_s2c_bytes != new_hot.direct_relay_copy_buf_s2c_bytes
    {
        info!(
            "config reload: relay_tuning: me_d2c_frames={} me_d2c_bytes={} me_d2c_delay_us={} me_ack_flush_immediate={} direct_buf_c2s={} direct_buf_s2c={}",
            new_hot.me_d2c_flush_batch_max_frames,
            new_hot.me_d2c_flush_batch_max_bytes,
            new_hot.me_d2c_flush_batch_max_delay_us,
            new_hot.me_d2c_ack_flush_immediate,
            new_hot.direct_relay_copy_buf_c2s_bytes,
            new_hot.direct_relay_copy_buf_s2c_bytes,
        );
    }

    if old_hot.users != new_hot.users {
        let mut added: Vec<&String> = new_hot.users.keys()
            .filter(|u| !old_hot.users.contains_key(*u))
            .collect();
        added.sort();

        let mut removed: Vec<&String> = old_hot.users.keys()
            .filter(|u| !new_hot.users.contains_key(*u))
            .collect();
        removed.sort();

        let mut changed: Vec<&String> = new_hot.users.keys()
            .filter(|u| {
                old_hot.users.get(*u)
                    .map(|s| s != &new_hot.users[*u])
                    .unwrap_or(false)
            })
            .collect();
        changed.sort();

        if !added.is_empty() {
            info!(
                "config reload: users added: [{}]",
                added.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
            let host = resolve_link_host(new_cfg, detected_ip_v4, detected_ip_v6);
            let port = new_cfg.general.links.public_port.unwrap_or(new_cfg.server.port);
            for user in &added {
                if let Some(secret) = new_hot.users.get(*user) {
                    print_user_links(user, secret, &host, port, new_cfg);
                }
            }
        }
        if !removed.is_empty() {
            info!(
                "config reload: users removed: [{}]",
                removed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
        if !changed.is_empty() {
            info!(
                "config reload: users secret changed: [{}]",
                changed.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            );
        }
    }

    if old_hot.user_max_tcp_conns != new_hot.user_max_tcp_conns {
        info!(
            "config reload: user_max_tcp_conns updated ({} entries)",
            new_hot.user_max_tcp_conns.len()
        );
    }
    if old_hot.user_expirations != new_hot.user_expirations {
        info!(
            "config reload: user_expirations updated ({} entries)",
            new_hot.user_expirations.len()
        );
    }
    if old_hot.user_data_quota != new_hot.user_data_quota {
        info!(
            "config reload: user_data_quota updated ({} entries)",
            new_hot.user_data_quota.len()
        );
    }
    if old_hot.user_max_unique_ips != new_hot.user_max_unique_ips {
        info!(
            "config reload: user_max_unique_ips updated ({} entries)",
            new_hot.user_max_unique_ips.len()
        );
    }
    if old_hot.user_max_unique_ips_global_each != new_hot.user_max_unique_ips_global_each
        || old_hot.user_max_unique_ips_mode != new_hot.user_max_unique_ips_mode
        || old_hot.user_max_unique_ips_window_secs
            != new_hot.user_max_unique_ips_window_secs
    {
        info!(
            "config reload: user_max_unique_ips policy global_each={} mode={:?} window={}s",
            new_hot.user_max_unique_ips_global_each,
            new_hot.user_max_unique_ips_mode,
            new_hot.user_max_unique_ips_window_secs
        );
    }
}

/// Load config, validate, diff against current, and broadcast if changed.
fn reload_config(
    config_path: &PathBuf,
    config_tx: &watch::Sender<Arc<ProxyConfig>>,
    log_tx: &watch::Sender<LogLevel>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
    reload_state: &mut ReloadState,
) -> Option<WatchManifest> {
    let loaded = match ProxyConfig::load_with_metadata(config_path) {
        Ok(loaded) => loaded,
        Err(e) => {
            error!("config reload: failed to parse {:?}: {}", config_path, e);
            return None;
        }
    };
    let LoadedConfig {
        config: new_cfg,
        source_files,
        rendered_hash,
    } = loaded;
    let next_manifest = WatchManifest::from_source_files(&source_files);

    if let Err(e) = new_cfg.validate() {
        error!("config reload: validation failed: {}; keeping old config", e);
        return Some(next_manifest);
    }

    if reload_state.is_applied(rendered_hash) {
        return Some(next_manifest);
    }

    let old_cfg = config_tx.borrow().clone();
    let applied_cfg = overlay_hot_fields(&old_cfg, &new_cfg);
    let old_hot = HotFields::from_config(&old_cfg);
    let applied_hot = HotFields::from_config(&applied_cfg);
    let non_hot_changed = !config_equal(&applied_cfg, &new_cfg);
    let hot_changed = old_hot != applied_hot;

    if non_hot_changed {
        warn_non_hot_changes(&old_cfg, &new_cfg, non_hot_changed);
    }

    if !hot_changed {
        reload_state.mark_applied(rendered_hash);
        return Some(next_manifest);
    }

    if old_hot.dns_overrides != applied_hot.dns_overrides
        && let Err(e) = crate::network::dns_overrides::install_entries(&applied_hot.dns_overrides)
    {
        error!(
            "config reload: invalid network.dns_overrides: {}; keeping old config",
            e
        );
        return Some(next_manifest);
    }

    log_changes(
        &old_hot,
        &applied_hot,
        &applied_cfg,
        log_tx,
        detected_ip_v4,
        detected_ip_v6,
    );
    config_tx.send(Arc::new(applied_cfg)).ok();
    reload_state.mark_applied(rendered_hash);
    Some(next_manifest)
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Spawn the hot-reload watcher task.
///
/// Uses `notify` (inotify on Linux) to detect file changes instantly.
/// SIGHUP is also handled on Unix as an additional manual trigger.
///
/// `detected_ip_v4` / `detected_ip_v6` are the IPs discovered during the
/// startup probe — used when generating proxy links for newly added users,
/// matching the same logic as the startup output.
pub fn spawn_config_watcher(
    config_path: PathBuf,
    initial: Arc<ProxyConfig>,
    detected_ip_v4: Option<IpAddr>,
    detected_ip_v6: Option<IpAddr>,
) -> (watch::Receiver<Arc<ProxyConfig>>, watch::Receiver<LogLevel>) {
    let initial_level = initial.general.log_level.clone();
    let (config_tx, config_rx) = watch::channel(initial);
    let (log_tx, log_rx)       = watch::channel(initial_level);

    let config_path = normalize_watch_path(&config_path);
    let initial_loaded = ProxyConfig::load_with_metadata(&config_path).ok();
    let initial_manifest = initial_loaded
        .as_ref()
        .map(|loaded| WatchManifest::from_source_files(&loaded.source_files))
        .unwrap_or_else(|| WatchManifest::from_source_files(std::slice::from_ref(&config_path)));
    let initial_snapshot_hash = initial_loaded.as_ref().map(|loaded| loaded.rendered_hash);

    tokio::spawn(async move {
        let (notify_tx, mut notify_rx) = mpsc::channel::<()>(4);
        let manifest_state = Arc::new(StdRwLock::new(WatchManifest::default()));
        let mut reload_state = ReloadState::new(initial_snapshot_hash);

        let tx_inotify = notify_tx.clone();
        let manifest_for_inotify = manifest_state.clone();
        let mut inotify_watcher = match recommended_watcher(move |res: notify::Result<notify::Event>| {
            let Ok(event) = res else { return };
            if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                return;
            }
            let is_our_file = manifest_for_inotify
                .read()
                .map(|manifest| manifest.matches_event_paths(&event.paths))
                .unwrap_or(false);
            if is_our_file {
                let _ = tx_inotify.try_send(());
            }
        }) {
            Ok(watcher) => Some(watcher),
            Err(e) => {
                warn!("config watcher: inotify unavailable: {}", e);
                None
            }
        };
        apply_watch_manifest(
            inotify_watcher.as_mut(),
            Option::<&mut notify::poll::PollWatcher>::None,
            &manifest_state,
            initial_manifest.clone(),
        );
        if inotify_watcher.is_some() {
            info!("config watcher: inotify active on {:?}", config_path);
        }

        let tx_poll = notify_tx.clone();
        let manifest_for_poll = manifest_state.clone();
        let mut poll_watcher = match notify::poll::PollWatcher::new(
            move |res: notify::Result<notify::Event>| {
                let Ok(event) = res else { return };
                if !matches!(event.kind, EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)) {
                    return;
                }
                let is_our_file = manifest_for_poll
                    .read()
                    .map(|manifest| manifest.matches_event_paths(&event.paths))
                    .unwrap_or(false);
                if is_our_file {
                    let _ = tx_poll.try_send(());
                }
            },
            notify::Config::default()
                .with_poll_interval(Duration::from_secs(3))
                .with_compare_contents(true),
        ) {
            Ok(watcher) => Some(watcher),
            Err(e) => {
                warn!("config watcher: poll watcher unavailable: {}", e);
                None
            }
        };
        apply_watch_manifest(
            Option::<&mut notify::RecommendedWatcher>::None,
            poll_watcher.as_mut(),
            &manifest_state,
            initial_manifest.clone(),
        );
        if poll_watcher.is_some() {
            info!("config watcher: poll watcher active (Docker/NFS safe)");
        }

        #[cfg(unix)]
        let mut sighup = {
            use tokio::signal::unix::{SignalKind, signal};
            signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler")
        };

        loop {
            #[cfg(unix)]
            tokio::select! {
                msg = notify_rx.recv() => {
                    if msg.is_none() { break; }
                }
                _ = sighup.recv() => {
                    info!("SIGHUP received — reloading {:?}", config_path);
                }
            }
            #[cfg(not(unix))]
            if notify_rx.recv().await.is_none() { break; }

            // Debounce: drain extra events that arrive within a short quiet window.
            tokio::time::sleep(HOT_RELOAD_DEBOUNCE).await;
            while notify_rx.try_recv().is_ok() {}

            let mut next_manifest = reload_config(
                &config_path,
                &config_tx,
                &log_tx,
                detected_ip_v4,
                detected_ip_v6,
                &mut reload_state,
            );
            if next_manifest.is_none() {
                tokio::time::sleep(HOT_RELOAD_DEBOUNCE).await;
                while notify_rx.try_recv().is_ok() {}
                next_manifest = reload_config(
                    &config_path,
                    &config_tx,
                    &log_tx,
                    detected_ip_v4,
                    detected_ip_v6,
                    &mut reload_state,
                );
            }

            if let Some(next_manifest) = next_manifest {
                apply_watch_manifest(
                    inotify_watcher.as_mut(),
                    poll_watcher.as_mut(),
                    &manifest_state,
                    next_manifest,
                );
            }
        }
    });

    (config_rx, log_rx)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> ProxyConfig {
        ProxyConfig::default()
    }

    fn write_reload_config(path: &Path, ad_tag: Option<&str>, server_port: Option<u16>) {
        let mut config = String::from(
            r#"
                [censorship]
                tls_domain = "example.com"

                [access.users]
                user = "00000000000000000000000000000000"
            "#,
        );

        if ad_tag.is_some() {
            config.push_str("\n[general]\n");
            if let Some(tag) = ad_tag {
                config.push_str(&format!("ad_tag = \"{tag}\"\n"));
            }
        }

        if let Some(port) = server_port {
            config.push_str("\n[server]\n");
            config.push_str(&format!("port = {port}\n"));
        }

        std::fs::write(path, config).unwrap();
    }

    fn temp_config_path(prefix: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("{prefix}_{nonce}.toml"))
    }

    #[test]
    fn overlay_applies_hot_and_preserves_non_hot() {
        let old = sample_config();
        let mut new = old.clone();
        new.general.hardswap = !old.general.hardswap;
        new.server.port = old.server.port.saturating_add(1);

        let applied = overlay_hot_fields(&old, &new);
        assert_eq!(applied.general.hardswap, new.general.hardswap);
        assert_eq!(applied.server.port, old.server.port);
    }

    #[test]
    fn non_hot_only_change_does_not_change_hot_snapshot() {
        let old = sample_config();
        let mut new = old.clone();
        new.server.port = old.server.port.saturating_add(1);

        let applied = overlay_hot_fields(&old, &new);
        assert_eq!(HotFields::from_config(&old), HotFields::from_config(&applied));
        assert_eq!(applied.server.port, old.server.port);
    }

    #[test]
    fn bind_stale_mode_is_hot() {
        let old = sample_config();
        let mut new = old.clone();
        new.general.me_bind_stale_mode = match old.general.me_bind_stale_mode {
            MeBindStaleMode::Never => MeBindStaleMode::Ttl,
            MeBindStaleMode::Ttl => MeBindStaleMode::Always,
            MeBindStaleMode::Always => MeBindStaleMode::Never,
        };

        let applied = overlay_hot_fields(&old, &new);
        assert_eq!(
            applied.general.me_bind_stale_mode,
            new.general.me_bind_stale_mode
        );
        assert_ne!(HotFields::from_config(&old), HotFields::from_config(&applied));
    }

    #[test]
    fn keepalive_is_not_hot() {
        let old = sample_config();
        let mut new = old.clone();
        new.general.me_keepalive_interval_secs = old.general.me_keepalive_interval_secs + 5;

        let applied = overlay_hot_fields(&old, &new);
        assert_eq!(
            applied.general.me_keepalive_interval_secs,
            old.general.me_keepalive_interval_secs
        );
        assert_eq!(HotFields::from_config(&old), HotFields::from_config(&applied));
    }

    #[test]
    fn mixed_hot_and_non_hot_change_applies_only_hot_subset() {
        let old = sample_config();
        let mut new = old.clone();
        new.general.hardswap = !old.general.hardswap;
        new.general.use_middle_proxy = !old.general.use_middle_proxy;

        let applied = overlay_hot_fields(&old, &new);
        assert_eq!(applied.general.hardswap, new.general.hardswap);
        assert_eq!(applied.general.use_middle_proxy, old.general.use_middle_proxy);
        assert!(!config_equal(&applied, &new));
    }

    #[test]
    fn reload_applies_hot_change_on_first_observed_snapshot() {
        let initial_tag = "11111111111111111111111111111111";
        let final_tag = "22222222222222222222222222222222";
        let path = temp_config_path("telemt_hot_reload_stable");

        write_reload_config(&path, Some(initial_tag), None);
        let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
        let initial_hash = ProxyConfig::load_with_metadata(&path).unwrap().rendered_hash;
        let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
        let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
        let mut reload_state = ReloadState::new(Some(initial_hash));

        write_reload_config(&path, Some(final_tag), None);
        reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();
        assert_eq!(config_tx.borrow().general.ad_tag.as_deref(), Some(final_tag));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reload_keeps_hot_apply_when_non_hot_fields_change() {
        let initial_tag = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let final_tag = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let path = temp_config_path("telemt_hot_reload_mixed");

        write_reload_config(&path, Some(initial_tag), None);
        let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
        let initial_hash = ProxyConfig::load_with_metadata(&path).unwrap().rendered_hash;
        let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
        let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
        let mut reload_state = ReloadState::new(Some(initial_hash));

        write_reload_config(&path, Some(final_tag), Some(initial_cfg.server.port + 1));
        reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();

        let applied = config_tx.borrow().clone();
        assert_eq!(applied.general.ad_tag.as_deref(), Some(final_tag));
        assert_eq!(applied.server.port, initial_cfg.server.port);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reload_recovers_after_parse_error_on_next_attempt() {
        let initial_tag = "cccccccccccccccccccccccccccccccc";
        let final_tag = "dddddddddddddddddddddddddddddddd";
        let path = temp_config_path("telemt_hot_reload_parse_recovery");

        write_reload_config(&path, Some(initial_tag), None);
        let initial_cfg = Arc::new(ProxyConfig::load(&path).unwrap());
        let initial_hash = ProxyConfig::load_with_metadata(&path).unwrap().rendered_hash;
        let (config_tx, _config_rx) = watch::channel(initial_cfg.clone());
        let (log_tx, _log_rx) = watch::channel(initial_cfg.general.log_level.clone());
        let mut reload_state = ReloadState::new(Some(initial_hash));

        std::fs::write(&path, "[access.users\nuser = \"broken\"\n").unwrap();
        assert!(reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).is_none());
        assert_eq!(
            config_tx.borrow().general.ad_tag.as_deref(),
            Some(initial_tag)
        );

        write_reload_config(&path, Some(final_tag), None);
        reload_config(&path, &config_tx, &log_tx, None, None, &mut reload_state).unwrap();
        assert_eq!(config_tx.borrow().general.ad_tag.as_deref(), Some(final_tag));

        let _ = std::fs::remove_file(path);
    }
}
