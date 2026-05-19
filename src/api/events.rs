use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

#[derive(Clone, Serialize)]
pub(super) struct ApiEventRecord {
    pub(super) seq: u64,
    pub(super) ts_epoch_secs: u64,
    pub(super) event_type: String,
    pub(super) context: String,
}

#[derive(Clone, Serialize)]
pub(super) struct ApiEventSnapshot {
    pub(super) capacity: usize,
    pub(super) dropped_total: u64,
    pub(super) events: Vec<ApiEventRecord>,
}

struct ApiEventsInner {
    capacity: usize,
    dropped_total: u64,
    next_seq: u64,
    events: VecDeque<ApiEventRecord>,
}

/// Bounded ring-buffer for control-plane API/runtime events.
pub(crate) struct ApiEventStore {
    inner: Mutex<ApiEventsInner>,
}

impl ApiEventStore {
    pub(super) fn new(capacity: usize) -> Self {
        let bounded = capacity.max(16);
        Self {
            inner: Mutex::new(ApiEventsInner {
                capacity: bounded,
                dropped_total: 0,
                next_seq: 1,
                events: VecDeque::with_capacity(bounded),
            }),
        }
    }

    pub(super) fn record(&self, event_type: &str, context: impl Into<String>) {
        let now_epoch_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let mut context = context.into();
        if context.len() > 256 {
            context.truncate(256);
        }

        let mut guard = self.inner.lock().expect("api event store mutex poisoned");
        if guard.events.len() == guard.capacity {
            guard.events.pop_front();
            guard.dropped_total = guard.dropped_total.saturating_add(1);
        }
        let seq = guard.next_seq;
        guard.next_seq = guard.next_seq.saturating_add(1);
        guard.events.push_back(ApiEventRecord {
            seq,
            ts_epoch_secs: now_epoch_secs,
            event_type: event_type.to_string(),
            context,
        });
    }

    pub(super) fn snapshot(&self, limit: usize) -> ApiEventSnapshot {
        let guard = self.inner.lock().expect("api event store mutex poisoned");
        let bounded_limit = limit.clamp(1, guard.capacity.max(1));
        let mut items: Vec<ApiEventRecord> = guard
            .events
            .iter()
            .rev()
            .take(bounded_limit)
            .cloned()
            .collect();
        items.reverse();

        ApiEventSnapshot {
            capacity: guard.capacity,
            dropped_total: guard.dropped_total,
            events: items,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_enforces_minimum_capacity() {
        // Anything below 16 should be promoted to 16.
        for requested in [0, 1, 5, 15] {
            let store = ApiEventStore::new(requested);
            assert_eq!(store.snapshot(1).capacity, 16, "requested={}", requested);
        }
        let store = ApiEventStore::new(64);
        assert_eq!(store.snapshot(1).capacity, 64);
    }

    #[test]
    fn record_then_snapshot_returns_events_in_order() {
        let store = ApiEventStore::new(16);
        store.record("a", "ctx-a");
        store.record("b", "ctx-b");
        store.record("c", "ctx-c");

        let snap = store.snapshot(10);
        assert_eq!(snap.events.len(), 3);
        assert_eq!(snap.events[0].event_type, "a");
        assert_eq!(snap.events[1].event_type, "b");
        assert_eq!(snap.events[2].event_type, "c");
        assert_eq!(snap.events[0].seq, 1);
        assert_eq!(snap.events[1].seq, 2);
        assert_eq!(snap.events[2].seq, 3);
        assert_eq!(snap.dropped_total, 0);
    }

    #[test]
    fn ring_buffer_evicts_oldest_and_tracks_dropped() {
        let store = ApiEventStore::new(16); // 16 is the enforced minimum.
        for i in 0..20u64 {
            store.record("e", format!("{}", i));
        }
        let snap = store.snapshot(100);
        assert_eq!(snap.events.len(), 16);
        assert_eq!(snap.dropped_total, 4);
        // First retained event should be index 4 (0..3 evicted).
        assert_eq!(snap.events[0].context, "4");
        assert_eq!(snap.events[15].context, "19");
        // Sequence numbers keep growing across evictions.
        assert_eq!(snap.events[0].seq, 5);
        assert_eq!(snap.events[15].seq, 20);
    }

    #[test]
    fn snapshot_limit_clamps_high_and_low() {
        let store = ApiEventStore::new(16);
        for i in 0..10u64 {
            store.record("e", format!("{}", i));
        }
        // limit=0 → clamped up to 1.
        let snap = store.snapshot(0);
        assert_eq!(snap.events.len(), 1);
        assert_eq!(snap.events[0].context, "9");
        // limit much larger than capacity → clamped to capacity.
        let snap = store.snapshot(usize::MAX);
        assert_eq!(snap.events.len(), 10);
        assert_eq!(snap.events[0].context, "0");
        // Mid-range limit returns the most recent N.
        let snap = store.snapshot(3);
        assert_eq!(snap.events.len(), 3);
        assert_eq!(snap.events[0].context, "7");
        assert_eq!(snap.events[2].context, "9");
    }

    #[test]
    fn context_is_truncated_to_256_bytes() {
        let store = ApiEventStore::new(16);
        let long = "x".repeat(500);
        store.record("big", long);

        let snap = store.snapshot(1);
        assert_eq!(snap.events[0].context.len(), 256);
        assert!(snap.events[0].context.chars().all(|c| c == 'x'));
    }

    #[test]
    fn empty_store_returns_empty_snapshot() {
        let store = ApiEventStore::new(32);
        let snap = store.snapshot(5);
        assert!(snap.events.is_empty());
        assert_eq!(snap.dropped_total, 0);
        assert_eq!(snap.capacity, 32);
    }

    #[test]
    fn record_timestamp_is_recent() {
        let store = ApiEventStore::new(16);
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        store.record("t", "now");
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let snap = store.snapshot(1);
        let ts = snap.events[0].ts_epoch_secs;
        assert!(ts >= before && ts <= after, "ts={ts}, before={before}, after={after}");
    }
}
