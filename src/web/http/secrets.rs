use hyper::Request;

use super::capability::{canonical_credential, scan_capabilities};
use crate::config::WebRuntimeConfig;
use crate::web::manager::WebProcessRuntime;

/// Request extension proving that metadata contains an authentic internal credential.
#[derive(Clone, Copy)]
struct InternalCredential;

/// Marks requests whose metadata contains a capability or process token.
pub(super) fn mark_internal_credential<B>(
    request: &mut Request<B>,
    config: &WebRuntimeConfig,
    runtime: &WebProcessRuntime,
) {
    let found = visit_metadata(request, |candidate| {
        bool::from(scan_capabilities(&config.capabilities, candidate).matched)
            || runtime.authentic_token(candidate)
            || runtime
                .wildcard
                .as_ref()
                .is_some_and(|cache| cache.contains(candidate))
    });
    if found {
        mark(request);
    }
}

/// Marks a request after a full selected-host capability scan authenticated metadata.
pub(super) fn mark<B>(request: &mut Request<B>) {
    request.extensions_mut().insert(InternalCredential);
}

/// Visits canonical raw or percent-decoded credential windows without allocating.
pub(super) fn visit_metadata<B>(
    request: &Request<B>,
    mut visit: impl FnMut(&[u8; 32]) -> bool,
) -> bool {
    let uri = request.uri();
    uri.authority()
        .is_some_and(|value| visit_text(value.as_str().as_bytes(), &mut visit))
        || uri
            .path_and_query()
            .is_some_and(|value| visit_text(value.as_str().as_bytes(), &mut visit))
        || request.headers().iter().any(|(name, value)| {
            visit_text(name.as_str().as_bytes(), &mut visit)
                || visit_text(value.as_bytes(), &mut visit)
        })
}

/// Returns whether request metadata was authenticated before routing.
pub(super) fn has_internal_credential<B>(request: &Request<B>) -> bool {
    request.extensions().get::<InternalCredential>().is_some()
}

fn visit_text(text: &[u8], visit: &mut impl FnMut(&[u8; 32]) -> bool) -> bool {
    let mut window = [0; 43];
    let mut run_len = 0usize;
    let mut offset = 0usize;
    while offset < text.len() {
        let (byte, consumed) = if text[offset] == b'%' && offset + 2 < text.len() {
            match (hex_value(text[offset + 1]), hex_value(text[offset + 2])) {
                (Some(high), Some(low)) => ((high << 4) | low, 3),
                _ => (text[offset], 1),
            }
        } else {
            (text[offset], 1)
        };
        offset += consumed;
        if base64url_byte(byte) {
            if run_len < window.len() {
                window[run_len] = byte;
                run_len += 1;
            } else {
                window.copy_within(1.., 0);
                window[42] = byte;
            }
            if run_len >= window.len()
                && canonical_credential(&window).is_some_and(|candidate| visit(&candidate))
            {
                return true;
            }
        } else {
            run_len = 0;
        }
    }
    false
}

fn base64url_byte(value: u8) -> bool {
    value.is_ascii_alphanumeric() || matches!(value, b'-' | b'_')
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
#[path = "secrets/tests.rs"]
mod tests;

#[cfg(test)]
fn contains_secret(text: &[u8], config: &WebRuntimeConfig, runtime: &WebProcessRuntime) -> bool {
    visit_text(text, &mut |candidate| {
        bool::from(scan_capabilities(&config.capabilities, candidate).matched)
            || runtime.authentic_token(candidate)
    })
}
