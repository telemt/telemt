//! Configuration data model split by serialized responsibility.
//!
//! Each private submodule owns one stable group of existing TOML fields while
//! this facade preserves the public crate configuration surface.

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use super::defaults::*;

mod access;
mod api;
mod censorship;
mod general;
mod general_impl;
mod links;
mod logging;
mod network;
mod policies;
mod server;
mod web;
// WEB carrier tokens and fixed-slot policy helpers remain independent from bulky config types.
mod web_carrier;
// WEB debug capture policy is reusable by config reload and process storage.
mod web_debug;

pub use access::{AccessConfig, CidrRateLimitKey, RateLimitBps};
#[allow(unused_imports)]
pub(crate) use access::{CidrAutoTemplate, CidrAutoTemplateFamily};
pub use api::{ApiConfig, ApiGrayAction};
pub use censorship::{
    AntiCensorshipConfig, ExclusiveMaskTarget, TlsFetchConfig, TlsFetchProfile, UnknownSniAction,
};
pub use general::GeneralConfig;
pub use links::{LinksConfig, ShowLink};
pub use logging::{LogLevel, LogRotation, LoggingConfig, LoggingDestination};
pub use network::{NetworkConfig, ProxyModes, UpstreamConfig, UpstreamType};
pub use policies::{
    MeBindStaleMode, MeFloorMode, MeRouteNoWriterMode, MeSocksKdfPolicy, MeTelemetryLevel,
    MeWriterPickMode, RstOnCloseMode, TelemetryConfig, UserMaxUniqueIpsMode,
};
#[allow(unused_imports)]
pub use server::{
    CLIENT_MSS_2IN8, CLIENT_MSS_EXTREME_LOW, CLIENT_MSS_MAX, CLIENT_MSS_MIN, CLIENT_MSS_TSPU,
    ConntrackBackend, ConntrackControlConfig, ConntrackMode, ConntrackPressureProfile,
    ListenerConfig, ListenerTransport, ServerConfig, SynLimitMode, TimeoutsConfig,
    WebClientIpSource,
};
#[allow(unused_imports)]
pub use web::{
    WebCarrierNegotiationAggressiveness, WebConfig, WebDecoyConfig,
    WebHttpConnectionCapacityAction, WebLimitsConfig, WebProfileConfig, WebSecretMode,
    WebTimeoutsConfig, WebVhostConfig,
};
pub(crate) use web::{
    WebRuntimeConfig, WebRuntimeDecoy, WebRuntimeProfile, WebRuntimeVhost, WebStaticAsset,
    WebStaticSite,
};
#[allow(unused_imports)]
pub use web_carrier::{WebCarrier, WebCarriers};
pub(crate) use web_debug::web_debug_fits_limits;
pub use web_debug::{WebDebugBodyCapture, WebDebugConfig};

fn default_quota_state_path() -> PathBuf {
    PathBuf::from("telemt.limit.json")
}
