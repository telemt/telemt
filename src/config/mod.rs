//! Configuration.

pub(crate) mod defaults;
pub mod hot_reload;
mod load;
mod types;

pub use load::ProxyConfig;
pub(crate) use load::{expand_config_includes, expand_config_includes_with_sources};
pub use types::*;
