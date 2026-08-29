use std::net::IpAddr;
use std::time::Instant;

use super::state::{ManagerState, allow_rate};
use super::{ProfileKey, WebProcessRuntime};
use crate::config::WebRuntimeProfile;
use crate::web::telemetry::WebRejectionReason;

/// Applies process, address, profile, and rate ceilings to one initial session.
pub(super) fn admit_initial(
    runtime: &WebProcessRuntime,
    state: &mut ManagerState,
    now: Instant,
    client_ip: IpAddr,
    profile_key: ProfileKey,
    profile: &WebRuntimeProfile,
) -> bool {
    if state.sessions.len() >= runtime.limits.max_sessions_global
        || state.sessions_per_ip.get(&client_ip).copied().unwrap_or(0)
            >= runtime.limits.max_sessions_per_ip
        || state
            .sessions_per_profile
            .get(&profile_key)
            .copied()
            .unwrap_or(0)
            >= profile.max_sessions
    {
        runtime.record_limit_hit();
        runtime
            .telemetry
            .record_rejection(WebRejectionReason::SessionCapacity);
        return false;
    }
    if !allow_rate(
        &mut state.session_rate,
        now,
        runtime.limits.new_sessions_per_minute,
        runtime.limits.new_sessions_burst,
    ) {
        runtime.record_limit_hit();
        runtime
            .telemetry
            .record_rejection(WebRejectionReason::SessionRate);
        return false;
    }
    true
}
