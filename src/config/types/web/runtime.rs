use super::*;

/// Precomputed WEB configuration consumed by listener hot paths.
#[derive(Debug, Default)]
pub(crate) struct WebRuntimeConfig {
    /// Process-unique immutable WEB snapshot identity, including same-generation reloads.
    pub(crate) snapshot_id: u64,
    /// Suffix index without the leading wildcard and dot.
    pub(crate) wildcards: BTreeMap<String, Arc<WebRuntimeVhost>>,
    /// Lowest-priority whole-group fallback.
    pub(crate) catch_all: Option<Arc<WebRuntimeVhost>>,
    /// Canonical host lookup used by HTTP request routing.
    pub(crate) vhosts: BTreeMap<String, Arc<WebRuntimeVhost>>,
    /// Flat profile inventory used by startup link emission.
    pub(crate) profiles: Vec<Arc<WebRuntimeProfile>>,
    /// Finite exact-host capability table used to contain misplaced credentials.
    pub(crate) capabilities: Box<[[u8; 32]]>,
}

/// Precomputed immutable virtual-host data.
#[derive(Debug)]
pub(crate) struct WebRuntimeVhost {
    /// Shared automatic-host policy; exact hosts keep their precomputed bindings.
    pub(crate) wildcard: Option<WebRuntimeWildcard>,
    /// Canonical lowercase ACE hostname; empty for a wildcard template.
    #[cfg(test)]
    pub(crate) host: String,
    /// Exact slash-delimited endpoint base, including the trailing slash.
    pub(crate) base: String,
    /// Restart-frozen decoy capability-scan policy.
    pub(crate) decoy_fasttrack_mode: WebDecoyFastTrackMode,
    /// Immutable ordinary-site fallback snapshot.
    pub(crate) decoy: Arc<WebRuntimeDecoy>,
    /// Upstream connect and response-head deadline.
    pub(crate) decoy_header_secs: u64,
    /// Precomputed exact-host profiles; wildcard policies live in `wildcard`.
    pub(crate) profiles: Vec<Arc<WebRuntimeProfile>>,
    /// Contiguous capability table aligned one-to-one with `profiles`.
    pub(crate) capabilities: Box<[[u8; 32]]>,
}

/// Authenticated exact-host profile binding.
#[derive(Debug)]
pub(crate) struct WebRuntimeProfile {
    /// Canonical host that owns this profile.
    pub(crate) host: String,
    /// HMAC-derived capability bound to this exact host and endpoint base.
    pub(crate) capability: [u8; 32],
    /// Immutable policy shared within a source group, never the quota owner.
    pub(crate) shared: Arc<WebRuntimeProfileShared>,
}

/// Host-independent profile policy retained by all bindings in one source group.
/// Limits still apply to each binding's exact host/user/mode quota owner.
#[derive(Debug)]
pub(crate) struct WebRuntimeProfileShared {
    /// Full domain-separated secret, protocol-version, and endpoint identity.
    pub(crate) derivation_context: [u8; 32],
    /// Stable public destination tuple supplied to relay routing.
    pub(crate) public_addr: SocketAddr,
    /// Exact access user authenticated by logical streams.
    pub(crate) user: String,
    /// Stable credential identity used by process-wide admission fencing.
    pub(crate) credential_id: [u8; 16],
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
    /// Fixed private origin prepared before the generation is published.
    HttpUpstream {
        /// Resolved destination, independent of the request Host.
        addr: SocketAddr,
        /// Configured origin authority forwarded to the upstream server.
        authority: String,
    },
    /// Immutable files acquired once for the entire source group.
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

/// Host-independent wildcard group, never a session or quota owner.
#[derive(Debug)]
pub(crate) struct WebRuntimeWildcard {
    /// Source-group identity local to the immutable WEB snapshot.
    pub(crate) group_id: usize,
    /// Ordered shared policies aligned with cold capability derivation.
    pub(crate) profiles: Vec<Arc<WebRuntimeProfileShared>>,
}

impl WebRuntimeConfig {
    /// Selects exactly one group: exact, longest suffix, then catch-all.
    pub(crate) fn route(&self, host: &str) -> Option<&Arc<WebRuntimeVhost>> {
        if let Some(vhost) = self.vhosts.get(host) {
            return Some(vhost);
        }
        for (offset, _) in host.match_indices('.') {
            if let Some(vhost) = self.wildcards.get(&host[offset + 1..]) {
                return Some(vhost);
            }
        }
        self.catch_all.as_ref()
    }
}
