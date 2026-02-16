//! Middle Proxy RPC transport.

mod codec;
mod health;
mod pool;
mod pool_nat;
mod reader;
mod registry;
mod send;
mod secret;
mod config_updater;
mod wire;

use bytes::Bytes;

pub use health::me_health_monitor;
pub use pool::MePool;
pub use pool_nat::{stun_probe, StunProbeResult};
pub use registry::ConnRegistry;
pub use secret::fetch_proxy_secret;
pub use config_updater::{fetch_proxy_config, me_config_updater};
pub use wire::proto_flags_for_tag;

#[derive(Debug)]
pub enum MeResponse {
    Data { flags: u32, data: Bytes },
    Ack(u32),
    Close,
}
