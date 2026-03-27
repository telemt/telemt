//! Middle Proxy RPC transport.

mod codec;
mod config_updater;
mod handshake;
mod health;
#[cfg(test)]
#[path = "tests/health_adversarial_tests.rs"]
mod health_adversarial_tests;
#[cfg(test)]
#[path = "tests/health_integration_tests.rs"]
mod health_integration_tests;
#[cfg(test)]
#[path = "tests/health_regression_tests.rs"]
mod health_regression_tests;
mod http_fetch;
mod ping;
mod pool;
mod pool_config;
mod pool_init;
mod pool_nat;
mod pool_refill;
#[cfg(test)]
#[path = "tests/pool_refill_security_tests.rs"]
mod pool_refill_security_tests;
mod pool_reinit;
mod pool_runtime_api;
mod pool_status;
mod pool_writer;
#[cfg(test)]
#[path = "tests/pool_writer_security_tests.rs"]
mod pool_writer_security_tests;
mod reader;
mod registry;
mod rotation;
mod secret;
mod selftest;
mod send;
#[cfg(test)]
#[path = "tests/send_adversarial_tests.rs"]
mod send_adversarial_tests;
mod wire;

use bytes::Bytes;

#[allow(unused_imports)]
pub use config_updater::{
    ProxyConfigData, fetch_proxy_config, fetch_proxy_config_via_upstream,
    fetch_proxy_config_with_raw, fetch_proxy_config_with_raw_via_upstream, load_proxy_config_cache,
    me_config_updater, save_proxy_config_cache,
};
pub use health::{me_drain_timeout_enforcer, me_health_monitor, me_zombie_writer_watchdog};
#[allow(unused_imports)]
pub use ping::{
    MePingFamily, MePingReport, MePingSample, format_me_route, format_sample_line, run_me_ping,
};
pub use pool::MePool;
#[allow(unused_imports)]
pub use pool_nat::{detect_public_ip, stun_probe};
pub use registry::ConnRegistry;
pub use rotation::{MeReinitTrigger, me_reinit_scheduler, me_rotation_task};
#[allow(unused_imports)]
pub use secret::{fetch_proxy_secret, fetch_proxy_secret_with_upstream};
pub(crate) use selftest::{bnd_snapshot, timeskew_snapshot, upstream_bnd_snapshots};
pub use wire::proto_flags_for_tag;

#[derive(Debug)]
pub enum MeResponse {
    Data { flags: u32, data: Bytes },
    Ack(u32),
    Close,
}
