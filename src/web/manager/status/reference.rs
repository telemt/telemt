use super::*;

/// Opaque session-reference validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionRefError {
    /// The reference does not use the canonical versioned shape.
    Invalid,
    /// The reference belongs to another process runtime.
    StaleInstance,
}

/// Tests immutable candidate fields before any optional state-lock read.
pub(in crate::web::manager) fn immutable_matches(
    session: &crate::web::session::WebSession,
    index: &crate::web::manager::state::LiveSessionIndex,
    filter: &SessionFilter,
) -> bool {
    filter
        .trace_session_id
        .is_none_or(|value| value == session.trace_session_id())
        && filter
            .client_ip
            .is_none_or(|value| value == session.client_ip())
        && filter
            .host
            .as_deref()
            .is_none_or(|value| value == session.profile_host())
        && filter
            .user
            .as_deref()
            .is_none_or(|value| value == session.profile_user())
        && filter
            .key_id
            .as_deref()
            .is_none_or(|value| session.key_id() == value)
        && filter
            .carrier
            .is_none_or(|value| value == session.carrier())
        && filter
            .user_agent_id
            .is_none_or(|value| index.user_agent_id == Some(value))
}

pub(super) fn permits(semaphore: &Arc<tokio::sync::Semaphore>, capacity: usize) -> PermitStatus {
    let available = semaphore.available_permits().min(capacity);
    PermitStatus {
        used: capacity.saturating_sub(available),
        available,
        capacity,
        closed: semaphore.is_closed(),
    }
}
