use std::cmp::Reverse;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::ProxyConfig;

use super::ApiShared;
use super::events::ApiEventRecord;

const FEATURE_DISABLED_REASON: &str = "feature_disabled";
const SOURCE_UNAVAILABLE_REASON: &str = "source_unavailable";
const EVENTS_DEFAULT_LIMIT: usize = 50;
const EVENTS_MAX_LIMIT: usize = 1000;

#[derive(Clone, Serialize)]
pub(super) struct RuntimeEdgeConnectionUserData {
    pub(super) username: String,
    pub(super) current_connections: u64,
    pub(super) total_octets: u64,
}

#[derive(Clone, Serialize)]
pub(super) struct RuntimeEdgeConnectionTotalsData {
    pub(super) current_connections: u64,
    pub(super) current_connections_me: u64,
    pub(super) current_connections_direct: u64,
    pub(super) active_users: usize,
}

#[derive(Clone, Serialize)]
pub(super) struct RuntimeEdgeConnectionTopData {
    pub(super) limit: usize,
    pub(super) by_connections: Vec<RuntimeEdgeConnectionUserData>,
    pub(super) by_throughput: Vec<RuntimeEdgeConnectionUserData>,
}

#[derive(Clone, Serialize)]
pub(super) struct RuntimeEdgeConnectionCacheData {
    pub(super) ttl_ms: u64,
    pub(super) served_from_cache: bool,
    pub(super) stale_cache_used: bool,
}

#[derive(Clone, Serialize)]
pub(super) struct RuntimeEdgeConnectionTelemetryData {
    pub(super) user_enabled: bool,
    pub(super) throughput_is_cumulative: bool,
}

#[derive(Clone, Serialize)]
pub(super) struct RuntimeEdgeConnectionsSummaryPayload {
    pub(super) cache: RuntimeEdgeConnectionCacheData,
    pub(super) totals: RuntimeEdgeConnectionTotalsData,
    pub(super) top: RuntimeEdgeConnectionTopData,
    pub(super) telemetry: RuntimeEdgeConnectionTelemetryData,
}

#[derive(Serialize)]
pub(super) struct RuntimeEdgeConnectionsSummaryData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<RuntimeEdgeConnectionsSummaryPayload>,
}

#[derive(Clone)]
pub(crate) struct EdgeConnectionsCacheEntry {
    pub(super) expires_at: Instant,
    pub(super) payload: RuntimeEdgeConnectionsSummaryPayload,
    pub(super) generated_at_epoch_secs: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeEdgeEventsPayload {
    pub(super) capacity: usize,
    pub(super) dropped_total: u64,
    pub(super) events: Vec<ApiEventRecord>,
}

#[derive(Serialize)]
pub(super) struct RuntimeEdgeEventsData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<RuntimeEdgeEventsPayload>,
}

pub(super) async fn build_runtime_connections_summary_data(
    shared: &ApiShared,
    cfg: &ProxyConfig,
) -> RuntimeEdgeConnectionsSummaryData {
    let now_epoch_secs = now_epoch_secs();
    let api_cfg = &cfg.server.api;
    if !api_cfg.runtime_edge_enabled {
        return RuntimeEdgeConnectionsSummaryData {
            enabled: false,
            reason: Some(FEATURE_DISABLED_REASON),
            generated_at_epoch_secs: now_epoch_secs,
            data: None,
        };
    }

    let (generated_at_epoch_secs, payload) = match get_connections_payload_cached(
        shared,
        api_cfg.runtime_edge_cache_ttl_ms,
        api_cfg.runtime_edge_top_n,
    )
    .await
    {
        Some(v) => v,
        None => {
            return RuntimeEdgeConnectionsSummaryData {
                enabled: true,
                reason: Some(SOURCE_UNAVAILABLE_REASON),
                generated_at_epoch_secs: now_epoch_secs,
                data: None,
            };
        }
    };

    RuntimeEdgeConnectionsSummaryData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs,
        data: Some(payload),
    }
}

pub(super) fn build_runtime_events_recent_data(
    shared: &ApiShared,
    cfg: &ProxyConfig,
    query: Option<&str>,
) -> RuntimeEdgeEventsData {
    let now_epoch_secs = now_epoch_secs();
    let api_cfg = &cfg.server.api;
    if !api_cfg.runtime_edge_enabled {
        return RuntimeEdgeEventsData {
            enabled: false,
            reason: Some(FEATURE_DISABLED_REASON),
            generated_at_epoch_secs: now_epoch_secs,
            data: None,
        };
    }

    let limit = parse_recent_events_limit(query, EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT);
    let snapshot = shared.runtime_events.snapshot(limit);

    RuntimeEdgeEventsData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs: now_epoch_secs,
        data: Some(RuntimeEdgeEventsPayload {
            capacity: snapshot.capacity,
            dropped_total: snapshot.dropped_total,
            events: snapshot.events,
        }),
    }
}

async fn get_connections_payload_cached(
    shared: &ApiShared,
    cache_ttl_ms: u64,
    top_n: usize,
) -> Option<(u64, RuntimeEdgeConnectionsSummaryPayload)> {
    if cache_ttl_ms > 0 {
        let now = Instant::now();
        let cached = shared.runtime_edge_connections_cache.lock().await.clone();
        if let Some(entry) = cached
            && now < entry.expires_at
        {
            let mut payload = entry.payload;
            payload.cache.served_from_cache = true;
            payload.cache.stale_cache_used = false;
            return Some((entry.generated_at_epoch_secs, payload));
        }
    }

    let Ok(_guard) = shared.runtime_edge_recompute_lock.try_lock() else {
        let cached = shared.runtime_edge_connections_cache.lock().await.clone();
        if let Some(entry) = cached {
            let mut payload = entry.payload;
            payload.cache.served_from_cache = true;
            payload.cache.stale_cache_used = true;
            return Some((entry.generated_at_epoch_secs, payload));
        }
        return None;
    };

    let generated_at_epoch_secs = now_epoch_secs();
    let payload = recompute_connections_payload(shared, cache_ttl_ms, top_n).await;

    if cache_ttl_ms > 0 {
        let entry = EdgeConnectionsCacheEntry {
            expires_at: Instant::now() + Duration::from_millis(cache_ttl_ms),
            payload: payload.clone(),
            generated_at_epoch_secs,
        };
        *shared.runtime_edge_connections_cache.lock().await = Some(entry);
    }

    Some((generated_at_epoch_secs, payload))
}

async fn recompute_connections_payload(
    shared: &ApiShared,
    cache_ttl_ms: u64,
    top_n: usize,
) -> RuntimeEdgeConnectionsSummaryPayload {
    let mut rows = Vec::<RuntimeEdgeConnectionUserData>::new();
    let mut active_users = 0usize;
    for entry in shared.stats.iter_user_stats() {
        let user_stats = entry.value();
        let current_connections = user_stats
            .curr_connects
            .load(std::sync::atomic::Ordering::Relaxed);
        let total_octets = user_stats
            .octets_from_client
            .load(std::sync::atomic::Ordering::Relaxed)
            .saturating_add(
                user_stats
                    .octets_to_client
                    .load(std::sync::atomic::Ordering::Relaxed),
            );
        if current_connections > 0 {
            active_users = active_users.saturating_add(1);
        }
        rows.push(RuntimeEdgeConnectionUserData {
            username: entry.key().clone(),
            current_connections,
            total_octets,
        });
    }

    let limit = top_n.max(1);
    let mut by_connections = rows.clone();
    by_connections.sort_by_key(|row| (Reverse(row.current_connections), row.username.clone()));
    by_connections.truncate(limit);

    let mut by_throughput = rows;
    by_throughput.sort_by_key(|row| (Reverse(row.total_octets), row.username.clone()));
    by_throughput.truncate(limit);

    let telemetry = shared.stats.telemetry_policy();
    RuntimeEdgeConnectionsSummaryPayload {
        cache: RuntimeEdgeConnectionCacheData {
            ttl_ms: cache_ttl_ms,
            served_from_cache: false,
            stale_cache_used: false,
        },
        totals: RuntimeEdgeConnectionTotalsData {
            current_connections: shared.stats.get_current_connections_total(),
            current_connections_me: shared.stats.get_current_connections_me(),
            current_connections_direct: shared.stats.get_current_connections_direct(),
            active_users,
        },
        top: RuntimeEdgeConnectionTopData {
            limit,
            by_connections,
            by_throughput,
        },
        telemetry: RuntimeEdgeConnectionTelemetryData {
            user_enabled: telemetry.user_enabled,
            throughput_is_cumulative: true,
        },
    }
}

fn parse_recent_events_limit(query: Option<&str>, default_limit: usize, max_limit: usize) -> usize {
    let Some(query) = query else {
        return default_limit;
    };
    for pair in query.split('&') {
        let mut split = pair.splitn(2, '=');
        if split.next() == Some("limit")
            && let Some(raw) = split.next()
            && let Ok(parsed) = raw.parse::<usize>()
        {
            return parsed.clamp(1, max_limit);
        }
    }
    default_limit
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
