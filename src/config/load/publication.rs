use std::sync::atomic::{AtomicU64, Ordering};

use super::ProxyConfig;

impl ProxyConfig {
    /// Identifies a publication, including a return to an earlier value. This is
    /// not a guarantee that asynchronous policy consumers have converged.
    pub(crate) fn with_publication_epoch(mut self) -> Self {
        static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
        self.runtime_config_epoch = NEXT_EPOCH.fetch_add(1, Ordering::Relaxed);
        self
    }
}
