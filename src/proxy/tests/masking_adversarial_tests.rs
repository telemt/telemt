use super::*;
use crate::config::ProxyConfig;
use crate::proxy::relay::relay_bidirectional;
use crate::stats::Stats;
use crate::stats::beobachten::BeobachtenStore;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant};

// ------------------------------------------------------------------
// Probing Indistinguishability (OWASP ASVS 5.1.7)
// ------------------------------------------------------------------

// Masking timing, fallback, and relay boundary cases.
#[path = "masking_adversarial_tests/boundaries.rs"]
mod boundaries;
// Concurrent reconnect storms and manual soak cases.
#[path = "masking_adversarial_tests/chaos.rs"]
mod chaos;
