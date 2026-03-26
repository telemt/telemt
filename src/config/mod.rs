//! Configuration.

pub(crate) mod defaults;
pub mod hot_reload;
mod load;
mod types;

pub use load::ProxyConfig;
pub use types::*;
