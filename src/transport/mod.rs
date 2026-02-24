//! Transport layer: connection pooling, socket utilities, proxy protocol

pub mod pool;
pub mod proxy_protocol;
pub mod socket;
pub mod socks;
pub mod upstream;

#[allow(unused_imports)]
pub use pool::ConnectionPool;
#[allow(unused_imports)]
pub use proxy_protocol::{ProxyProtocolInfo, parse_proxy_protocol};
pub use socket::*;
#[allow(unused_imports)]
pub use socks::*;
#[allow(unused_imports)]
pub use upstream::{DcPingResult, StartupPingResult, UpstreamManager};
pub mod middle_proxy;
