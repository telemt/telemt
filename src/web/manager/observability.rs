use serde::Serialize;

use super::WebProcessRuntime;

/// Current usage of one fixed process-wide WEB resource.
#[derive(Clone, Serialize)]
pub(crate) struct WebCapacityResourceStatus {
    /// Stable closed-set resource token.
    pub(crate) resource: &'static str,
    /// Stable unit used by API consumers and metric-family routing.
    pub(crate) unit: &'static str,
    /// Currently retained capacity.
    pub(crate) used: usize,
    /// Unretained portion of the immutable ceiling before class-specific reserves.
    pub(crate) available: usize,
    /// Immutable process-wide ceiling.
    pub(crate) limit: usize,
    /// Whether terminal shutdown closed this allocation authority.
    pub(crate) closed: bool,
}

/// Non-blocking fixed-cardinality capacity snapshot.
#[derive(Clone, Serialize)]
pub(crate) struct WebCapacitySnapshot {
    /// Exact fixed process-wide resources available without dynamic labels.
    pub(crate) resources: Vec<WebCapacityResourceStatus>,
    /// Resources with no immediately available capacity.
    pub(crate) saturated_resources: Vec<&'static str>,
    /// Snapshot planes omitted because their short lock was contended.
    pub(crate) partial: Vec<&'static str>,
}

impl WebProcessRuntime {
    /// Captures fixed global resource usage without blocking the data plane.
    pub(crate) fn capacity_snapshot(&self) -> WebCapacitySnapshot {
        let websocket_capacity = self
            .limits
            .max_http_connections
            .saturating_sub(self.limits.websocket_http_connection_reserve);
        let mut resources = vec![
            semaphore_status(
                "http_connections",
                "slots",
                &self.http_connections,
                self.limits.max_http_connections,
            ),
            semaphore_status(
                "http_overload_connections",
                "slots",
                &self.http_overload_connections,
                self.limits.max_http_overload_connections,
            ),
            semaphore_status(
                "http_handlers",
                "slots",
                &self.http_handlers,
                self.limits.max_http_handlers,
            ),
            semaphore_status(
                "lane_polls",
                "slots",
                &self.lane_polls,
                self.limits.max_http_handlers / 2,
            ),
            semaphore_status(
                "lane_aux_polls",
                "slots",
                &self.lane_aux_polls,
                (self.limits.max_http_handlers / 4).max(1),
            ),
            semaphore_status(
                "body_readers",
                "slots",
                &self.body_readers,
                self.limits.max_body_readers,
            ),
            semaphore_status(
                "body_bytes",
                "bytes",
                &self.body_bytes,
                self.limits.max_body_bytes_global,
            ),
            semaphore_status(
                "stream_handshakes",
                "slots",
                &self.stream_handshakes,
                self.limits.max_stream_handshakes,
            ),
            semaphore_status(
                "websocket_connections",
                "slots",
                &self.websocket_connections,
                websocket_capacity,
            ),
        ];
        let mut partial = Vec::new();
        if let Some(budget) = self.data_budget.try_snapshot() {
            resources.extend([
                bounded_status(
                    "pending_bytes",
                    "bytes",
                    budget.queue_bytes.saturating_add(budget.websocket_bytes),
                    self.limits.pending_bytes_global,
                    budget.closed,
                ),
                bounded_status(
                    "queue_items",
                    "items",
                    budget.queue_items,
                    self.limits.pending_items_global,
                    budget.closed,
                ),
                bounded_status(
                    "websocket_bytes",
                    "bytes",
                    budget.websocket_bytes,
                    self.limits.websocket_bytes_global,
                    budget.closed,
                ),
            ]);
        } else {
            partial.push("budget");
        }
        let saturated_resources = resources
            .iter()
            .filter(|status| status.available == 0 && !status.closed)
            .map(|status| status.resource)
            .collect();
        WebCapacitySnapshot {
            resources,
            saturated_resources,
            partial,
        }
    }
}

fn semaphore_status(
    resource: &'static str,
    unit: &'static str,
    semaphore: &tokio::sync::Semaphore,
    limit: usize,
) -> WebCapacityResourceStatus {
    let available = semaphore.available_permits().min(limit);
    WebCapacityResourceStatus {
        resource,
        unit,
        used: limit.saturating_sub(available),
        available,
        limit,
        closed: semaphore.is_closed(),
    }
}

fn bounded_status(
    resource: &'static str,
    unit: &'static str,
    used: usize,
    limit: usize,
    closed: bool,
) -> WebCapacityResourceStatus {
    let used = used.min(limit);
    WebCapacityResourceStatus {
        resource,
        unit,
        used,
        available: limit.saturating_sub(used),
        limit,
        closed,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::sync::Semaphore;

    #[test]
    fn semaphore_status_reports_usage_and_available_capacity() {
        let semaphore = Arc::new(Semaphore::new(3));
        let _permit = semaphore.clone().try_acquire_owned().unwrap();
        let status = super::semaphore_status("test", "slots", &semaphore, 3);
        assert_eq!(status.used, 1);
        assert_eq!(status.available, 2);
        assert_eq!(status.limit, 3);
    }
}
