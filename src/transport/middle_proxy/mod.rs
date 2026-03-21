//! Middle Proxy RPC transport.

mod codec;
mod config_updater;
mod handshake;
mod health;
mod pool;
mod pool_config;
mod pool_init;
mod pool_nat;
mod pool_refill;
mod pool_reinit;
mod pool_runtime_api;
mod pool_writer;
mod ping;
mod reader;
mod registry;
mod rotation;
mod send;
mod secret;
mod selftest;
mod wire;
mod pool_status;
#[cfg(test)]
#[path = "tests/health_regression_tests.rs"]
mod health_regression_tests;
#[cfg(test)]
#[path = "tests/health_integration_tests.rs"]
mod health_integration_tests;
#[cfg(test)]
#[path = "tests/health_adversarial_tests.rs"]
mod health_adversarial_tests;
#[cfg(test)]
#[path = "tests/send_adversarial_tests.rs"]
mod send_adversarial_tests;
#[cfg(test)]
#[path = "tests/pool_writer_security_tests.rs"]
mod pool_writer_security_tests;
#[cfg(test)]
#[path = "tests/pool_refill_security_tests.rs"]
mod pool_refill_security_tests;

use bytes::Bytes;

pub use health::{me_drain_timeout_enforcer, me_health_monitor, me_zombie_writer_watchdog};
#[allow(unused_imports)]
pub use ping::{run_me_ping, format_sample_line, format_me_route, MePingReport, MePingSample, MePingFamily};
pub use pool::MePool;
#[allow(unused_imports)]
pub use pool_nat::{stun_probe, detect_public_ip};
pub use registry::ConnRegistry;
pub use secret::fetch_proxy_secret;
#[allow(unused_imports)]
pub use config_updater::{
    ProxyConfigData, fetch_proxy_config, fetch_proxy_config_with_raw, load_proxy_config_cache,
    me_config_updater, save_proxy_config_cache,
};
pub use rotation::{MeReinitTrigger, me_reinit_scheduler, me_rotation_task};
pub(crate) use selftest::{
    bnd_snapshot, timeskew_snapshot, upstream_bnd_snapshots,
};
pub use wire::proto_flags_for_tag;

#[derive(Debug)]
pub enum MeResponse {
    Data { flags: u32, data: Bytes },
    Ack(u32),
    Close,
}
