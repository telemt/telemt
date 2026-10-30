use std::time::Instant;

use super::{ManagerState, remove_bootstrap_locked};

/// Removes expired credentials without changing the caller's expiry boundary.
pub(in crate::web::manager) fn remove_expired_locked(
    state: &mut ManagerState,
    now: Instant,
) -> usize {
    // None implies an empty map; Some may be stale, but never later than a live deadline.
    // Deletion and bootstrap renewal only leave early hints, so one sweep repairs them.
    let mut recovery_unused = 0;
    if state.bootstrap_expiry.is_some_and(|expiry| now > expiry) {
        let mut next_expiry: Option<Instant> = None;
        let expired = state
            .bootstraps
            .iter()
            .filter_map(|(hash, bootstrap)| {
                if now <= bootstrap.expires_at {
                    if next_expiry.is_none_or(|expiry| bootstrap.expires_at < expiry) {
                        next_expiry = Some(bootstrap.expires_at);
                    }
                    None
                } else {
                    Some((*hash, bootstrap.recovery && !bootstrap.used))
                }
            })
            .collect::<Vec<_>>();
        recovery_unused = expired
            .iter()
            .filter(|(_, recovery_unused)| *recovery_unused)
            .count();
        for (hash, _) in expired {
            remove_bootstrap_locked(state, hash);
        }
        state.bootstrap_expiry = next_expiry;
    }
    if state.closed_token_expiry.is_some_and(|expiry| now > expiry) {
        let mut next_expiry: Option<Instant> = None;
        state.closed_tokens.retain(|_, closed| {
            if now > closed.expires_at {
                false
            } else {
                if next_expiry.is_none_or(|expiry| closed.expires_at < expiry) {
                    next_expiry = Some(closed.expires_at);
                }
                true
            }
        });
        state.closed_token_expiry = next_expiry;
    }
    // Logical-session tombstones have their own FIFO lifetime, independent of both maps.
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

#[cfg(test)]
mod tests;
