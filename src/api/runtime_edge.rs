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
pub struct EdgeConnectionsCacheEntry {
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

#[cfg(test)]
mod tests {
    use super::{parse_recent_events_limit, EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT};

    #[test]
    fn parse_recent_events_limit_with_none_query_returns_default() {
        assert_eq!(
            parse_recent_events_limit(None, EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            EVENTS_DEFAULT_LIMIT
        );
    }

    #[test]
    fn parse_recent_events_limit_with_empty_query_returns_default() {
        assert_eq!(
            parse_recent_events_limit(Some(""), EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            EVENTS_DEFAULT_LIMIT
        );
    }

    #[test]
    fn parse_recent_events_limit_parses_valid_midrange_value() {
        assert_eq!(
            parse_recent_events_limit(Some("limit=100"), EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            100
        );
    }

    // Adversarial: limit=0 must be clamped to 1 (minimum) to never produce an
    // empty response for a request that explicitly asked for events.
    #[test]
    fn parse_recent_events_limit_clamps_zero_to_one() {
        assert_eq!(
            parse_recent_events_limit(Some("limit=0"), EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            1
        );
    }

    // Adversarial: limit above EVENTS_MAX_LIMIT must be capped to prevent
    // allocating unbounded memory for the response body.
    #[test]
    fn parse_recent_events_limit_clamps_value_above_max() {
        let over_max = EVENTS_MAX_LIMIT + 1;
        assert_eq!(
            parse_recent_events_limit(
                Some(&format!("limit={over_max}")),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            EVENTS_MAX_LIMIT
        );
    }

    #[test]
    fn parse_recent_events_limit_accepts_exactly_max() {
        assert_eq!(
            parse_recent_events_limit(
                Some(&format!("limit={EVENTS_MAX_LIMIT}")),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            EVENTS_MAX_LIMIT
        );
    }

    // Adversarial: numeric overflow (value > usize::MAX) must not panic and
    // must fall back to the default limit.
    #[test]
    fn parse_recent_events_limit_overflow_integer_falls_back_to_default() {
        let overflow = "99999999999999999999999999999999";
        assert_eq!(
            parse_recent_events_limit(
                Some(&format!("limit={overflow}")),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            EVENTS_DEFAULT_LIMIT
        );
    }

    // Adversarial: negative values must not parse as usize (which is unsigned)
    // and must fall back to the default.
    #[test]
    fn parse_recent_events_limit_negative_value_falls_back_to_default() {
        assert_eq!(
            parse_recent_events_limit(Some("limit=-1"), EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            EVENTS_DEFAULT_LIMIT
        );
    }

    // The key name matching is case-sensitive; LIMIT or Limit must not match.
    #[test]
    fn parse_recent_events_limit_key_matching_is_case_sensitive() {
        assert_eq!(
            parse_recent_events_limit(Some("LIMIT=200"), EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            EVENTS_DEFAULT_LIMIT
        );
        assert_eq!(
            parse_recent_events_limit(Some("Limit=200"), EVENTS_DEFAULT_LIMIT, EVENTS_MAX_LIMIT),
            EVENTS_DEFAULT_LIMIT
        );
    }

    // Adversarial: a URL-encoded key like limit%3D50 must NOT match "limit" and
    // must fall back to the default (the query string is used raw, not decoded).
    #[test]
    fn parse_recent_events_limit_url_encoded_key_is_not_matched() {
        assert_eq!(
            parse_recent_events_limit(
                Some("limit%3D50"),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            EVENTS_DEFAULT_LIMIT
        );
    }

    // When the query string contains multiple "limit" keys, the first one wins.
    #[test]
    fn parse_recent_events_limit_uses_first_matching_key() {
        assert_eq!(
            parse_recent_events_limit(
                Some("limit=10&limit=900"),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            10
        );
    }

    // Other query params before "limit" must not prevent "limit" from being matched.
    #[test]
    fn parse_recent_events_limit_ignores_preceding_unrelated_params() {
        assert_eq!(
            parse_recent_events_limit(
                Some("foo=bar&limit=75"),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            75
        );
    }

    #[test]
    fn parse_recent_events_limit_with_no_limit_key_in_nonempty_query_returns_default() {
        assert_eq!(
            parse_recent_events_limit(
                Some("since=100&format=json"),
                EVENTS_DEFAULT_LIMIT,
                EVENTS_MAX_LIMIT
            ),
            EVENTS_DEFAULT_LIMIT
        );
    }
}
