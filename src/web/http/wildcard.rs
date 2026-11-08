use super::*;
use crate::config::{ProxyConfig, WebRuntimeProfile};
use crate::web::manager::wildcard::CapabilityTable;

/// Contains actual credentials and derives at most one selected-host table per request.
pub(super) fn prepare<B>(
    request: &mut Request<B>,
    config: &ProxyConfig,
    vhost: &WebRuntimeVhost,
    host: &str,
    runtime: &WebProcessRuntime,
) -> Result<Option<CapabilityTable>, ()> {
    // A process-authentic credential can never reach the decoy. Established carriers
    // need no host-table lookup, HMAC derivation or host binding allocation.
    let suffix = request.uri().path().strip_prefix(&vhost.base);
    if suffix
        .is_some_and(|suffix| TRANSPORT_SUFFIXES.contains(&suffix) || suffix == WEBSOCKET_SUFFIX)
        && runtime.wildcard.is_some()
        && secrets::visit_metadata(request, |candidate| runtime.authentic_token(candidate))
    {
        secrets::mark(request);
        return Ok(None);
    }
    let web = config.web.runtime.as_ref().ok_or(())?;
    secrets::mark_internal_credential(request, web, runtime);
    if vhost.wildcard.is_none() {
        return Ok(None);
    }
    let root_full_scan = request.uri().path() == vhost.base
        && matches!(*request.method(), Method::GET | Method::HEAD)
        && vhost.decoy_fasttrack_mode != WebDecoyFastTrackMode::Enforce;
    let candidate_present = secrets::visit_metadata(request, |_| true);
    if !root_full_scan && !candidate_present {
        return Ok(None);
    }
    let cache = runtime.wildcard.as_ref().ok_or(())?;
    let table = cache.prepare(config, vhost, host).ok_or(())?;
    if secrets::visit_metadata(request, |candidate| {
        bool::from(capability::scan_capabilities(table.capabilities(), candidate).matched)
    }) {
        secrets::mark(request);
    }
    Ok(Some(table))
}

/// Creates one host binding only after a complete constant-time capability scan.
pub(super) fn match_profile(
    vhost: &WebRuntimeVhost,
    host: &str,
    table: Option<&CapabilityTable>,
    candidate: &[u8; 32],
) -> Option<Arc<WebRuntimeProfile>> {
    let Some(group) = &vhost.wildcard else {
        return super::match_profile(vhost, candidate);
    };
    let capabilities = table?.capabilities();
    if capabilities.len() != group.profiles.len() {
        return None;
    }
    let scan = capability::scan_capabilities(capabilities, candidate);
    if !bool::from(scan.matched) {
        return None;
    }
    let shared = group
        .profiles
        .get(usize::try_from(scan.matched_index).ok()?)?;
    Some(Arc::new(WebRuntimeProfile {
        host: host.to_string(),
        capability: *candidate,
        shared: Arc::clone(shared),
    }))
}
