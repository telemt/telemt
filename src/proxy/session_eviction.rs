/// Session eviction is intentionally disabled in runtime.
///
/// The initial `user+dc` single-lease model caused valid parallel client
/// connections to evict each other. Keep the API shape for compatibility,
/// but make it a no-op until a safer policy is introduced.

#[derive(Debug, Clone, Default)]
pub struct SessionLease;

impl SessionLease {
    pub fn is_stale(&self) -> bool {
        false
    }

    #[allow(dead_code)]
    pub fn release(&self) {}
}

pub struct RegistrationResult {
    pub lease: SessionLease,
    pub replaced_existing: bool,
}

pub fn register_session(_user: &str, _dc_idx: i16) -> RegistrationResult {
    RegistrationResult {
        lease: SessionLease,
        replaced_existing: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_eviction_disabled_behavior() {
        let first = register_session("alice", 2);
        let second = register_session("alice", 2);
        assert!(!first.replaced_existing);
        assert!(!second.replaced_existing);
        assert!(!first.lease.is_stale());
        assert!(!second.lease.is_stale());
        first.lease.release();
        second.lease.release();
    }
}
