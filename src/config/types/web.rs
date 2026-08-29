use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use super::web_carrier::{WebCarrier, WebCarriers};
use super::web_debug::WebDebugConfig;

// Serialized WEB defaults remain separate from the runtime data model.
mod defaults;
use defaults::*;
// Accepted-socket overload policy remains separate from the bulky WEB data model.
mod overload;
pub use overload::WebHttpConnectionCapacityAction;

/// Client-facing secret representation used to derive a WEB capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebSecretMode {
    /// Use the existing 16-byte access secret without a prefix.
    Plain,
    /// Prefix the existing access secret with `0xdd` for capability derivation.
    Dd,
}

/// One access user explicitly exposed through a WEB virtual host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebProfileConfig {
    /// Existing `[access.users]` key authenticated by the inner MTProxy handshake.
    pub user: String,
    /// Exact client-facing secret representation advertised in WEB links.
    pub secret_mode: WebSecretMode,
    /// Optional per-profile live session ceiling.
    #[serde(default)]
    pub max_sessions: Option<usize>,
    /// Optional per-profile live logical-stream ceiling.
    #[serde(default)]
    pub max_streams: Option<usize>,
    /// Optional per-profile stream ceiling for one session.
    #[serde(default)]
    pub max_streams_per_session: Option<usize>,
}

/// Public-site fallback used for requests that are not authenticated WEB traffic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum WebDecoyConfig {
    /// Stream requests to one fixed private HTTP origin.
    HttpUpstream {
        /// Origin URL without a query or fragment.
        upstream: String,
    },
    /// Serve an immutable, bounded snapshot of a local directory.
    StaticDirectory {
        /// Absolute directory containing public files.
        directory: PathBuf,
        /// File served for `/` and directory paths.
        #[serde(default = "default_web_static_index")]
        index: String,
    },
}

/// One externally visible WEB hostname and its explicit access profiles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebVhostConfig {
    /// Canonical lowercase ACE hostname used by Telegram Desktop.
    pub host: String,
    /// Stable public destination tuple used by inner relay routing and KDF metadata.
    pub public_addr: SocketAddr,
    /// Ordinary-site fallback for this hostname.
    pub decoy: WebDecoyConfig,
    /// Access users and exact secret modes enabled for this hostname.
    #[serde(default)]
    pub profiles: Vec<WebProfileConfig>,
}

/// Hard process and protocol limits for WEB ingress.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebLimitsConfig {
    /// Maximum bytes accepted while parsing one HTTP request head.
    #[serde(default = "default_web_max_header_bytes")]
    pub max_header_bytes: usize,
    /// Maximum collected carrier request body size.
    #[serde(default = "default_web_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Maximum payload carried by one WEB frame.
    #[serde(default = "default_web_max_frame_payload_bytes")]
    pub max_frame_payload_bytes: usize,
    /// Maximum encoded downlink batch returned by one poll.
    #[serde(default = "default_web_carrier_batch_bytes")]
    pub carrier_batch_bytes: usize,
    /// Maximum frame count parsed or emitted in one carrier body.
    #[serde(default = "default_web_max_frames_per_body")]
    pub max_frames_per_body: usize,
    /// Process-wide accepted WEB HTTP connection ceiling.
    #[serde(default = "default_web_max_http_connections")]
    pub max_http_connections: usize,
    /// Accepted overload sockets allowed to wait or emit a retryable response.
    #[serde(default = "default_web_max_http_overload_connections")]
    pub max_http_overload_connections: usize,
    /// Process-wide concurrently executing HTTP handler ceiling.
    #[serde(default = "default_web_max_http_handlers")]
    pub max_http_handlers: usize,
    /// Per-session ceiling for downlink polls waiting for a lane OPEN.
    #[serde(default = "default_web_max_lane_open_waits_per_session")]
    pub max_lane_open_waits_per_session: usize,
    /// Queued and resident DATA bytes allowed for one independent lane.
    #[serde(default = "default_web_pending_bytes_per_lane")]
    pub pending_bytes_per_lane: usize,
    /// Queued and resident DATA items allowed for one independent lane.
    #[serde(default = "default_web_pending_items_per_lane")]
    pub pending_items_per_lane: usize,
    /// Process-wide transient WebSocket byte sub-budget inside pending bytes.
    #[serde(default = "default_web_websocket_bytes_global")]
    pub websocket_bytes_global: usize,
    /// WebSocket usage percentage above which ordinary admission uses replacement.
    #[serde(default = "default_web_websocket_admission_watermark_pct")]
    pub websocket_admission_watermark_pct: u8,
    /// WebSocket usage percentage that triggers pressure eviction.
    #[serde(default = "default_web_websocket_eviction_watermark_pct")]
    pub websocket_eviction_watermark_pct: u8,
    /// Accepted HTTP connections that WebSocket upgrades must leave available.
    #[serde(default = "default_web_websocket_http_connection_reserve")]
    pub websocket_http_connection_reserve: usize,
    /// Concurrent pressure-eviction claims allowed process-wide.
    #[serde(default = "default_web_max_websocket_evictions_in_flight")]
    pub max_websocket_evictions_in_flight: usize,
    /// Process-wide bounded carrier-learning evidence entry ceiling.
    #[serde(default = "default_web_max_carrier_learning_entries")]
    pub max_carrier_learning_entries: usize,
    /// Process-wide concurrently collected request body ceiling.
    #[serde(default = "default_web_max_body_readers")]
    pub max_body_readers: usize,
    /// Process-wide byte reservation for collected request bodies.
    #[serde(default = "default_web_max_body_bytes_global")]
    pub max_body_bytes_global: usize,
    /// Process-wide live WEB session ceiling.
    #[serde(default = "default_web_max_sessions_global")]
    pub max_sessions_global: usize,
    /// Live WEB session ceiling for one forwarded client address.
    #[serde(default = "default_web_max_sessions_per_ip")]
    pub max_sessions_per_ip: usize,
    /// Default live logical-stream ceiling for one WEB session.
    #[serde(default = "default_web_max_streams_per_session")]
    pub max_streams_per_session: usize,
    /// Process-wide live logical-stream ceiling.
    #[serde(default = "default_web_max_streams_global")]
    pub max_streams_global: usize,
    /// Process-wide ceiling for inner MTProxy handshakes that received a first byte.
    #[serde(default = "default_web_max_stream_handshakes")]
    pub max_stream_handshakes: usize,
    /// Closed stream identifiers retained by one session.
    #[serde(default = "default_web_max_tombstones")]
    pub max_tombstones_per_session: usize,
    /// Total queued data and control bytes allowed for one session.
    #[serde(default = "default_web_pending_bytes_per_session")]
    pub pending_bytes_per_session: usize,
    /// Process-wide queued data and control byte ceiling.
    #[serde(default = "default_web_pending_bytes_global")]
    pub pending_bytes_global: usize,
    /// Total queued data and control item ceiling for one session.
    #[serde(default = "default_web_pending_items_per_session")]
    pub pending_items_per_session: usize,
    /// Process-wide queued data and control item ceiling.
    #[serde(default = "default_web_pending_items_global")]
    pub pending_items_global: usize,
    /// Per-session byte reserve available only to control frames.
    #[serde(default = "default_web_control_bytes_per_session")]
    pub control_bytes_per_session: usize,
    /// Process-wide byte reserve available only to control frames.
    #[serde(default = "default_web_control_bytes_global")]
    pub control_bytes_global: usize,
    /// Process-wide live bootstrap credential ceiling.
    #[serde(default = "default_web_max_bootstraps_global")]
    pub max_bootstraps_global: usize,
    /// Live bootstrap credential ceiling for one forwarded client address.
    #[serde(default = "default_web_max_bootstraps_per_ip")]
    pub max_bootstraps_per_ip: usize,
    /// Maximum configured WEB virtual-host count.
    #[serde(default = "default_web_max_vhosts")]
    pub max_vhosts: usize,
    /// Maximum configured WEB access-profile count across all virtual hosts.
    #[serde(default = "default_web_max_profiles")]
    pub max_profiles: usize,
    /// Maximum static snapshot entry count across all virtual hosts.
    #[serde(default = "default_web_max_static_files")]
    pub max_static_files: usize,
    /// Maximum bytes read from one static snapshot file.
    #[serde(default = "default_web_max_static_file_bytes")]
    pub max_static_file_bytes: usize,
    /// Maximum static snapshot bytes across all virtual hosts.
    #[serde(default = "default_web_max_static_bytes")]
    pub max_static_bytes: usize,
    /// Maximum retained WEB debug record count.
    #[serde(default = "default_web_debug_records_capacity")]
    pub debug_records_capacity: usize,
    /// Process-wide retained and in-flight WEB debug byte ceiling.
    #[serde(default = "default_web_debug_bytes_global")]
    pub debug_bytes_global: usize,
    /// Declared process envelope for HTTP, queues, lane state, learning, and static snapshots.
    #[serde(default = "default_web_memory_envelope_bytes")]
    pub memory_envelope_bytes: usize,
    /// Sustained process-wide bootstrap issuance rate.
    #[serde(default = "default_web_new_bootstraps_per_minute")]
    pub new_bootstraps_per_minute: u32,
    /// Process-wide bootstrap issuance burst.
    #[serde(default = "default_web_new_bootstraps_burst")]
    pub new_bootstraps_burst: u32,
    /// Sustained process-wide session creation rate.
    #[serde(default = "default_web_new_sessions_per_minute")]
    pub new_sessions_per_minute: u32,
    /// Process-wide session creation burst.
    #[serde(default = "default_web_new_sessions_burst")]
    pub new_sessions_burst: u32,
    /// Sustained process-wide logical-stream creation rate.
    #[serde(default = "default_web_new_streams_per_minute")]
    pub new_streams_per_minute: u32,
    /// Process-wide logical-stream creation burst.
    #[serde(default = "default_web_new_streams_burst")]
    pub new_streams_burst: u32,
}

impl Default for WebLimitsConfig {
    fn default() -> Self {
        Self {
            max_header_bytes: default_web_max_header_bytes(),
            max_body_bytes: default_web_max_body_bytes(),
            max_frame_payload_bytes: default_web_max_frame_payload_bytes(),
            carrier_batch_bytes: default_web_carrier_batch_bytes(),
            max_frames_per_body: default_web_max_frames_per_body(),
            max_http_connections: default_web_max_http_connections(),
            max_http_overload_connections: default_web_max_http_overload_connections(),
            max_http_handlers: default_web_max_http_handlers(),
            max_lane_open_waits_per_session: default_web_max_lane_open_waits_per_session(),
            pending_bytes_per_lane: default_web_pending_bytes_per_lane(),
            pending_items_per_lane: default_web_pending_items_per_lane(),
            websocket_bytes_global: default_web_websocket_bytes_global(),
            websocket_admission_watermark_pct: default_web_websocket_admission_watermark_pct(),
            websocket_eviction_watermark_pct: default_web_websocket_eviction_watermark_pct(),
            websocket_http_connection_reserve: default_web_websocket_http_connection_reserve(),
            max_websocket_evictions_in_flight: default_web_max_websocket_evictions_in_flight(),
            max_carrier_learning_entries: default_web_max_carrier_learning_entries(),
            max_body_readers: default_web_max_body_readers(),
            max_body_bytes_global: default_web_max_body_bytes_global(),
            max_sessions_global: default_web_max_sessions_global(),
            max_sessions_per_ip: default_web_max_sessions_per_ip(),
            max_streams_per_session: default_web_max_streams_per_session(),
            max_streams_global: default_web_max_streams_global(),
            max_stream_handshakes: default_web_max_stream_handshakes(),
            max_tombstones_per_session: default_web_max_tombstones(),
            pending_bytes_per_session: default_web_pending_bytes_per_session(),
            pending_bytes_global: default_web_pending_bytes_global(),
            pending_items_per_session: default_web_pending_items_per_session(),
            pending_items_global: default_web_pending_items_global(),
            control_bytes_per_session: default_web_control_bytes_per_session(),
            control_bytes_global: default_web_control_bytes_global(),
            max_bootstraps_global: default_web_max_bootstraps_global(),
            max_bootstraps_per_ip: default_web_max_bootstraps_per_ip(),
            max_vhosts: default_web_max_vhosts(),
            max_profiles: default_web_max_profiles(),
            max_static_files: default_web_max_static_files(),
            max_static_file_bytes: default_web_max_static_file_bytes(),
            max_static_bytes: default_web_max_static_bytes(),
            debug_records_capacity: default_web_debug_records_capacity(),
            debug_bytes_global: default_web_debug_bytes_global(),
            memory_envelope_bytes: default_web_memory_envelope_bytes(),
            new_bootstraps_per_minute: default_web_new_bootstraps_per_minute(),
            new_bootstraps_burst: default_web_new_bootstraps_burst(),
            new_sessions_per_minute: default_web_new_sessions_per_minute(),
            new_sessions_burst: default_web_new_sessions_burst(),
            new_streams_per_minute: default_web_new_streams_per_minute(),
            new_streams_burst: default_web_new_streams_burst(),
        }
    }
}

/// Deadlines for WEB HTTP, bootstrap, session, and shutdown lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebTimeoutsConfig {
    /// Deadline for receiving one complete HTTP request head.
    #[serde(default = "default_web_header_timeout_secs")]
    pub header_secs: u64,
    /// Deadline for collecting one authenticated carrier request body.
    #[serde(default = "default_web_body_timeout_secs")]
    pub body_secs: u64,
    /// Deadline from the first inner byte through MTProxy authentication.
    #[serde(default = "default_web_stream_handshake_timeout_secs")]
    pub stream_handshake_secs: u64,
    /// Absolute deadline for receiving the first inner MTProxy byte.
    #[serde(default = "default_web_stream_first_byte_secs")]
    pub stream_first_byte_secs: u64,
    /// Maximum wait for one empty downlink long poll.
    #[serde(default = "default_web_long_poll_timeout_secs")]
    pub long_poll_secs: u64,
    /// Deadline for one generated-bridge HTTP attempt and response body.
    #[serde(default = "default_web_bridge_request_secs")]
    pub bridge_request_secs: u64,
    /// Absolute generated-bridge budget for one retryable HTTP operation.
    #[serde(default = "default_web_bridge_retry_secs")]
    pub bridge_retry_secs: u64,
    /// Optional delay for coalescing the first OPEN with immediate DATA.
    #[serde(default = "default_web_carrier_probe_coalesce_ms")]
    pub carrier_probe_coalesce_ms: u64,
    /// Grace for a canonical downlink poll that races its lane OPEN.
    #[serde(default = "default_web_lane_open_wait_secs")]
    pub lane_open_wait_secs: u64,
    /// Post-commit observation interval required before learning succeeds.
    #[serde(default = "default_web_carrier_health_secs")]
    pub carrier_health_secs: u64,
    /// Maximum wait for Hyper to transfer an accepted WebSocket upgrade.
    #[serde(default = "default_web_websocket_upgrade_secs")]
    pub websocket_upgrade_secs: u64,
    /// Absolute deadline for the first carrier binary message after upgrade.
    #[serde(default = "default_web_websocket_open_secs")]
    pub websocket_open_secs: u64,
    /// Maximum wait for one WebSocket write to complete.
    #[serde(default = "default_web_websocket_write_secs")]
    pub websocket_write_secs: u64,
    /// Maximum wait for WebSocket queue or byte-budget progress.
    #[serde(default = "default_web_websocket_backpressure_secs")]
    pub websocket_backpressure_secs: u64,
    /// Maximum graceful close wait for an evicted WebSocket.
    #[serde(default = "default_web_websocket_eviction_secs")]
    pub websocket_eviction_secs: u64,
    /// Cumulative carrier-attempt deadlines for up to four unique candidates.
    #[serde(default = "default_web_carrier_negotiation_deadlines_secs")]
    pub carrier_negotiation_deadlines_secs: [u64; 4],
    /// Fixed process-local carrier-learning evidence lifetime.
    #[serde(default = "default_web_carrier_learning_secs")]
    pub carrier_learning_secs: u64,
    /// Lifetime of an unused bootstrap credential and closed-token replay marker.
    #[serde(default = "default_web_bootstrap_lifetime_secs")]
    pub bootstrap_lifetime_secs: u64,
    /// Maximum carrier inactivity before a session is closed.
    #[serde(default = "default_web_reconnect_grace_secs")]
    pub reconnect_grace_secs: u64,
    /// Maximum idle lifetime of a WEB HTTP keep-alive connection.
    #[serde(default = "default_web_http_idle_secs")]
    pub http_idle_secs: u64,
    /// Per-phase wait or response deadline for accepted HTTP overload sockets.
    #[serde(default = "default_web_http_overload_timeout_ms")]
    pub http_overload_timeout_ms: u64,
    /// Maximum graceful wait for WEB connections and process-owned tasks.
    #[serde(default = "default_web_shutdown_secs")]
    pub shutdown_secs: u64,
    /// Deadline for connecting to and receiving headers from an HTTP decoy.
    #[serde(default = "default_web_decoy_header_timeout_secs")]
    pub decoy_header_secs: u64,
}

impl Default for WebTimeoutsConfig {
    fn default() -> Self {
        Self {
            header_secs: default_web_header_timeout_secs(),
            body_secs: default_web_body_timeout_secs(),
            stream_handshake_secs: default_web_stream_handshake_timeout_secs(),
            stream_first_byte_secs: default_web_stream_first_byte_secs(),
            long_poll_secs: default_web_long_poll_timeout_secs(),
            bridge_request_secs: default_web_bridge_request_secs(),
            bridge_retry_secs: default_web_bridge_retry_secs(),
            carrier_probe_coalesce_ms: default_web_carrier_probe_coalesce_ms(),
            lane_open_wait_secs: default_web_lane_open_wait_secs(),
            carrier_health_secs: default_web_carrier_health_secs(),
            websocket_upgrade_secs: default_web_websocket_upgrade_secs(),
            websocket_open_secs: default_web_websocket_open_secs(),
            websocket_write_secs: default_web_websocket_write_secs(),
            websocket_backpressure_secs: default_web_websocket_backpressure_secs(),
            websocket_eviction_secs: default_web_websocket_eviction_secs(),
            carrier_negotiation_deadlines_secs: default_web_carrier_negotiation_deadlines_secs(),
            carrier_learning_secs: default_web_carrier_learning_secs(),
            bootstrap_lifetime_secs: default_web_bootstrap_lifetime_secs(),
            reconnect_grace_secs: default_web_reconnect_grace_secs(),
            http_idle_secs: default_web_http_idle_secs(),
            http_overload_timeout_ms: default_web_http_overload_timeout_ms(),
            shutdown_secs: default_web_shutdown_secs(),
            decoy_header_secs: default_web_decoy_header_timeout_secs(),
        }
    }
}

/// Sensitivity of process-local carrier-learning evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebCarrierNegotiationAggressiveness {
    /// Require broad evidence and never rank by client IP.
    #[default]
    Conservative,
    /// Use moderate User-Agent, client-IP, and profile thresholds.
    Balanced,
    /// React to the first bounded evidence sample.
    Aggressive,
}

/// WEB ingress, carrier, fallback, and lifecycle configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfig {
    /// Enables issuance of new WEB bridge and session credentials.
    #[serde(default)]
    pub enabled: bool,
    /// Sole carrier when negotiation is disabled and final fallback when enabled.
    #[serde(default)]
    pub carrier: WebCarrier,
    /// Ordered carriers considered by server-side negotiation before the fallback carrier.
    #[serde(default)]
    pub carriers: WebCarriers,
    /// Enables bounded process-local carrier learning for automatic sessions.
    #[serde(default = "default_web_carrier_learning")]
    pub carrier_learning: bool,
    /// Controls the evidence thresholds used by automatic carrier ranking.
    #[serde(default)]
    pub carrier_negotiation_aggressiveness: WebCarrierNegotiationAggressiveness,
    /// Action applied when accepted HTTP connection capacity is exhausted.
    #[serde(default)]
    pub http_connection_capacity_action: WebHttpConnectionCapacityAction,
    /// Hard process and protocol limits.
    #[serde(default)]
    pub limits: WebLimitsConfig,
    /// Hot-reloadable bounded server-side debug policy.
    #[serde(default)]
    pub debug: WebDebugConfig,
    /// WEB lifecycle deadlines.
    #[serde(default)]
    pub timeouts: WebTimeoutsConfig,
    /// Public hostnames served by WEB listeners.
    #[serde(default)]
    pub vhosts: Vec<WebVhostConfig>,
    /// Validated immutable runtime snapshot built during configuration loading.
    #[serde(skip)]
    pub(crate) runtime: Option<Arc<WebRuntimeConfig>>,
}

impl WebConfig {
    /// Returns the configured negotiation order with the fallback appended once.
    pub(crate) fn carrier_candidates(&self) -> Vec<WebCarrier> {
        let Some(configured) = self.carriers.enabled() else {
            return vec![self.carrier];
        };
        let mut candidates = configured
            .iter()
            .copied()
            .filter(|carrier| *carrier != self.carrier)
            .collect::<Vec<_>>();
        candidates.push(self.carrier);
        candidates
    }

    /// Returns whether the explicit candidate list enables auto-negotiation.
    pub(crate) fn carrier_negotiation_enabled(&self) -> bool {
        self.carriers.enabled().is_some()
    }
}

impl Default for WebConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            carrier: WebCarrier::default(),
            carriers: WebCarriers::default(),
            carrier_learning: default_web_carrier_learning(),
            carrier_negotiation_aggressiveness: WebCarrierNegotiationAggressiveness::default(),
            http_connection_capacity_action: WebHttpConnectionCapacityAction::default(),
            limits: WebLimitsConfig::default(),
            debug: WebDebugConfig::default(),
            timeouts: WebTimeoutsConfig::default(),
            vhosts: Vec::new(),
            runtime: None,
        }
    }
}

/// Precomputed WEB configuration consumed by listener hot paths.
#[derive(Debug)]
pub(crate) struct WebRuntimeConfig {
    /// Canonical host lookup used by HTTP request routing.
    pub(crate) vhosts: BTreeMap<String, Arc<WebRuntimeVhost>>,
    /// Flat profile inventory used by startup link emission.
    pub(crate) profiles: Vec<Arc<WebRuntimeProfile>>,
}

/// Precomputed immutable virtual-host data.
#[derive(Debug)]
pub(crate) struct WebRuntimeVhost {
    /// Canonical lowercase ACE hostname.
    pub(crate) host: String,
    /// Immutable ordinary-site fallback snapshot.
    pub(crate) decoy: WebRuntimeDecoy,
    /// Upstream connect and response-head deadline.
    pub(crate) decoy_header_secs: u64,
    /// Exact capability profiles accepted by this host.
    pub(crate) profiles: Vec<Arc<WebRuntimeProfile>>,
}

/// Precomputed exact-user capability entry.
#[derive(Debug)]
pub(crate) struct WebRuntimeProfile {
    /// Canonical host that owns this profile.
    pub(crate) host: String,
    /// Stable public destination tuple supplied to relay routing.
    pub(crate) public_addr: SocketAddr,
    /// Exact access user authenticated by logical streams.
    pub(crate) user: String,
    /// Client secret representation and inner protocol policy.
    pub(crate) secret_mode: WebSecretMode,
    /// Sole carrier or final fallback frozen into the issued bridge policy.
    pub(crate) carrier: WebCarrier,
    /// Whether an explicit carrier list enabled automatic negotiation.
    pub(crate) carrier_negotiation_enabled: bool,
    /// Whether automatic outcomes consult and update process-local evidence.
    pub(crate) carrier_learning: bool,
    /// Ordered negotiation candidates including the fallback carrier exactly once.
    pub(crate) carriers: Arc<[WebCarrier]>,
    /// Cumulative carrier-attempt deadlines frozen when the bridge is issued.
    pub(crate) carrier_negotiation_deadlines_secs: [u64; 4],
    /// HMAC-derived bridge capability.
    pub(crate) capability: [u8; 32],
    /// Non-secret domain-separated client-secret fingerprint for debugging.
    pub(crate) key_fingerprint: String,
    /// Per-profile live session ceiling.
    pub(crate) max_sessions: usize,
    /// Per-profile live logical-stream ceiling.
    pub(crate) max_streams: usize,
    /// Per-session live relay-task ceiling.
    pub(crate) max_streams_per_session: usize,
}

/// Runtime-ready ordinary-site fallback.
#[derive(Debug)]
pub(crate) enum WebRuntimeDecoy {
    HttpUpstream { addr: SocketAddr, authority: String },
    StaticDirectory(Arc<WebStaticSite>),
}

/// Immutable bounded static-site snapshot.
#[derive(Debug)]
pub(crate) struct WebStaticSite {
    /// Canonical URL-path to immutable response asset mapping.
    pub(crate) assets: BTreeMap<String, WebStaticAsset>,
    /// Configured root index file name.
    pub(crate) index: String,
}

/// One immutable static response body and metadata.
#[derive(Debug)]
pub(crate) struct WebStaticAsset {
    /// Immutable response body retained by the runtime snapshot.
    pub(crate) body: Bytes,
    /// Extension-derived static content type.
    pub(crate) content_type: &'static str,
    /// Strong SHA-256 entity tag.
    pub(crate) etag: String,
}
