//! Middle Proxy RPC transport.

mod codec;
mod handshake;
mod health;
mod pool;
mod pool_nat;
mod ping;
mod reader;
mod registry;
mod send;
mod secret;
mod rotation;
mod config_updater;
mod wire;

use bytes::Bytes;

pub use health::me_health_monitor;
#[allow(unused_imports)]
pub use ping::{run_me_ping, format_sample_line, MePingReport, MePingSample, MePingFamily};
pub use pool::MePool;
#[allow(unused_imports)]
pub use pool_nat::{stun_probe, detect_public_ip};
pub use registry::ConnRegistry;
pub use secret::fetch_proxy_secret;
pub use config_updater::{fetch_proxy_config, me_config_updater};
pub use rotation::me_rotation_task;
pub use wire::proto_flags_for_tag;

#[derive(Debug)]
pub enum MeResponse {
    Data { flags: u32, data: Bytes },
    Ack(u32),
    Close,
}
