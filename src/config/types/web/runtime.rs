use super::*;

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
