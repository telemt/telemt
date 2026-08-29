//! Client listener planning, binding, lifecycle control, and accept loops.
//!
//! Submodules keep process-owned socket state separate from generation-owned
//! runtime state:
//! - `plan` derives deterministic bind intent from validated configuration.
//! - `bind` prepares and activates sockets without partial startup binding.
//! - `accept` runs cancellation-aware TCP accept loops.
//! - `control` coordinates reversible listener transitions and shutdown.
//! - `web_overload` handles accepted WEB sockets outside ordinary capacity.

mod accept;
mod bind;
mod control;
mod plan;
#[cfg(unix)]
mod unix;
mod web_overload;

pub(crate) use bind::bind_listeners;
pub(crate) use control::{ListenerManager, PreparedListenerTransition};
pub(crate) use plan::listener_rebind_supported;

#[cfg(any(target_os = "linux", test))]
fn tcp_mss_runtime_profile(
    handshake_mss: Option<u16>,
    bulk_mss: Option<u16>,
) -> (Option<u16>, Option<u16>) {
    match (handshake_mss, bulk_mss) {
        (Some(fragment_size), Some(listener_mss)) => (Some(listener_mss), Some(fragment_size)),
        (listener_mss, None) => (listener_mss, None),
        (None, Some(_)) => (None, None),
    }
}

#[cfg(test)]
mod tests {
    use super::tcp_mss_runtime_profile;

    #[test]
    fn client_mss_without_bulk_remains_connection_wide() {
        assert_eq!(tcp_mss_runtime_profile(Some(92), None), (Some(92), None));
    }

    #[test]
    fn client_mss_with_bulk_uses_bulk_listener_and_chunks_initial_response() {
        assert_eq!(
            tcp_mss_runtime_profile(Some(92), Some(1400)),
            (Some(1400), Some(92))
        );
    }

    #[test]
    fn bulk_mss_without_handshake_mss_does_not_enable_shaping() {
        assert_eq!(tcp_mss_runtime_profile(None, Some(1400)), (None, None));
    }
}
