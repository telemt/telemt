//! Telegram Middle Proxy support
//!
//! # Architecture
//!
//! ```text
//! Client ←[TLS + AES-CTR + FrameCodec]→ Proxy
//!         ←[MTProto Frames + AES-CBC + RPC]→ Middle-Proxy DC
//! ```
//!
//! # Modules
//!
//! - [`config`]     — Runtime config: proxy secret, DC lists, background updates
//! - [`codec`]      — RPC message encoding / decoding
//! - [`handshake`]  — Nonce exchange + KDF + RPC handshake
//! - [`connection`] — `MiddleProxyStream`, `HandshakedMiddleConnection`
//! - [`relay`]      — Frame-level bidirectional relay
//! - [`pool`]       — Pre-handshaked connection pool

pub mod config;
pub mod codec;
pub mod handshake;
pub mod connection;
pub mod relay;
pub mod pool;

pub use config::MiddleProxyConfig;
pub use connection::{MiddleProxyStream, HandshakedMiddleConnection};
pub use handshake::{handshake_middle_proxy, connect_middle_proxy};
pub use relay::relay_middle_proxy;
pub use pool::MiddleProxyPool;