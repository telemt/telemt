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
