//! Hot-reload: watches the config file via inotify (Linux) / FSEvents (macOS)
//! / ReadDirectoryChangesW (Windows) using the `notify` crate.
//! SIGHUP is also supported on Unix as an additional manual trigger.
//!
//! # What can be reloaded without restart
//!
//! | Section   | Field                          | Effect                                         |
//! |-----------|--------------------------------|------------------------------------------------|
//! | `general` | `log_level`                    | Filter updated via `log_level_tx`              |
//! | `access`  | `user_ad_tags`                 | Passed on next connection                      |
//! | `general` | `ad_tag`                       | Passed on next connection (fallback per-user)  |
//! | `general` | `desync_all_full`              | Applied immediately                            |
//! | `general` | `update_every`                 | Applied to ME updater immediately              |
//! | `general` | `me_reinit_*`                  | Applied to ME reinit scheduler immediately     |
//! | `general` | `hardswap` / `me_*_reinit`     | Applied on next ME map update                  |
//! | `general` | `telemetry` / `me_*_policy`    | Applied immediately                            |
//! | `network` | `dns_overrides`                | Applied immediately                            |
//! | `access`  | All user/quota fields          | Effective immediately                          |
//! | `web`     | Carrier, timing, and debug policy | Applied to newly issued sessions             |
//! | `web`     | `carrier_method`               | Applied to newly rendered bridge pages        |
//! Fields that require re-binding sockets (`server.listeners`, legacy
//! `server.port`, `censorship.*`, `network.*`, `use_middle_proxy`) are **not**
//! applied; a warning is emitted. SYN limiter rules are process-owned and are
//! reconciled only during privileged startup.
//! `web.allow_wildcard_hosts, web.decoy_fasttrack_mode` is also restart-only so one process never mixes
//! capability timing policies or process-lifetime counter semantics.
//! Non-hot changes are never mixed into the runtime config snapshot.

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher, recommended_watcher};
use tokio::sync::{mpsc, watch};
use tracing::{error, info, warn};

use super::load::{LoadedConfig, ProxyConfig};
#[allow(unused_imports)]
use crate::config::{
    CidrRateLimitKey, LogLevel, MeBindStaleMode, MeFloorMode, MeSocksKdfPolicy, MeTelemetryLevel,
    MeWriterPickMode, WEB_CARRIER_LEARNING_MIN_ENTRIES, WebDebugConfig, web_debug_fits_limits,
};
#[cfg(test)]
use crate::config::{ListenerConfig, SynLimitMode};

const HOT_RELOAD_DEBOUNCE: Duration = Duration::from_millis(50);

mod diff;
mod fields;
mod reporting;
mod watcher;

#[allow(unused_imports)]
pub use diff::{ChangeClassification, classify_config_changes};
pub use fields::HotFields;
pub use watcher::spawn_config_watcher;

use diff::{config_equal, warn_non_hot_changes};
use fields::overlay_hot_fields;
use reporting::log_changes;
#[cfg(test)]
use watcher::{ReloadState, reload_config};

#[cfg(test)]
#[path = "hot_reload/base_path_tests.rs"]
mod base_path_tests;
#[cfg(test)]
mod tests;
// Carrier method reloads preserve page-owned requests and process-owned limits.
#[cfg(test)]
#[path = "hot_reload/carrier_method_tests.rs"]
mod carrier_method_tests;

#[cfg(test)]
#[path = "hot_reload/conveyor_tests.rs"]
mod conveyor_tests;

// Host groups are validated and published as one complete immutable snapshot.
#[cfg(test)]
mod host_list_tests;

#[cfg(test)]
mod quota_period_tests;
