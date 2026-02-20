//! Configuration.

pub(crate) mod defaults;
mod types;
mod load;
pub mod hot_reload;

pub use load::ProxyConfig;
pub use types::*;
