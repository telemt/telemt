// Frozen exhaustive sweep from the pre-optimization implementation.
use super::*;

/// Removes expired bootstrap and closed-token entries while the manager lock is held.
pub(super) fn exhaustive(state: &mut ManagerState, now: Instant) -> usize {
    let expired = state
        .bootstraps
        .iter()
        .filter_map(|(hash, bootstrap)| {
            (now > bootstrap.expires_at).then_some((*hash, bootstrap.recovery && !bootstrap.used))
        })
        .collect::<Vec<_>>();
    let recovery_unused = expired
        .iter()
        .filter(|(_, recovery_unused)| *recovery_unused)
        .count();
    for (hash, _) in expired {
        remove_bootstrap_locked(state, hash);
    }
    state
        .closed_tokens
        .retain(|_, closed| now <= closed.expires_at);
    while state
        .closed_session_order
        .front()
        .and_then(|trace_session_id| state.closed_sessions.get(trace_session_id))
        .is_some_and(|closed| now > closed.expires_at)
    {
        if let Some(trace_session_id) = state.closed_session_order.pop_front() {
            state.closed_sessions.remove(&trace_session_id);
        }
    }
    recovery_unused
}
