use std::sync::Arc;

use base64::Engine as _;
use hyper::Request;
use hyper::header;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::{WebRuntimeProfile, WebRuntimeVhost};
use crate::web::manager::{
    CarrierCapabilities, CarrierClientClass, CarrierFailure, CarrierRequest, TokenHash,
};

const USER_AGENT_CONTEXT: &[u8] = b"telemt-web-carrier-user-agent-v1\0";

use super::capability::scan_capabilities;

// Canonical host and forwarded-address provenance remain isolated from credentials.
mod identity;
pub(super) use identity::{
    canonical_request_host, carrier_ip_learning_eligible, client_ip, wildcard_request_host,
};

/// Matches one capability after a complete branchless scan of the virtual host table.
pub(super) fn match_profile(
    vhost: &WebRuntimeVhost,
    candidate: &[u8; 32],
) -> Option<Arc<WebRuntimeProfile>> {
    // Runtime construction owns alignment; any future constructor drift must fail closed.
    if vhost.capabilities.len() != vhost.profiles.len() {
        return None;
    }
    let scan = scan_capabilities(&vhost.capabilities, candidate);
    if bool::from(scan.matched) {
        usize::try_from(scan.matched_index)
            .ok()
            .and_then(|index| vhost.profiles.get(index))
            // Revalidate the selected identity after the index-only complete scan.
            .filter(|profile| bool::from(profile.capability.ct_eq(candidate)))
            .map(Arc::clone)
    } else {
        None
    }
}

/// Validates and hashes one canonical bearer credential for map lookup.
pub(super) fn bearer_token_hash<B>(request: &Request<B>) -> Option<TokenHash> {
    let values = request.headers().get_all(header::AUTHORIZATION);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || !value.starts_with("Bearer ") || value.matches(' ').count() != 1 {
        return None;
    }
    let token = value.strip_prefix("Bearer ")?;
    if token.len() != 43 {
        return None;
    }
    let mut decoded = [0u8; 32];
    let decoded_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode_slice(token, &mut decoded)
        .ok()?;
    let mut canonical = [0u8; 43];
    let encoded_len = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode_slice(decoded, &mut canonical)
        .ok()?;
    (decoded_len == decoded.len()
        && encoded_len == canonical.len()
        && bool::from(canonical.ct_eq(token.as_bytes())))
    .then(|| Sha256::digest(decoded).into())
}

/// Checks the exact carrier media type without accepting duplicate headers.
pub(super) fn binary_content_type<B>(request: &Request<B>) -> bool {
    let values = request.headers().get_all(header::CONTENT_TYPE);
    let mut values = values.iter();
    let value = values.next().and_then(|value| value.to_str().ok());
    values.next().is_none()
        && value.is_some_and(|value| value.eq_ignore_ascii_case("application/octet-stream"))
}

/// Accepts no Cookie or the one empty value emitted by restricted Windows WebView2.
pub(super) fn compatible_cookie_header<B>(request: &Request<B>) -> bool {
    let values = request.headers().get_all(header::COOKIE);
    let mut values = values.iter();
    match values.next() {
        None => true,
        Some(value) => value.as_bytes().is_empty() && values.next().is_none(),
    }
}

/// Parses one canonical unsigned decimal carrier sequence header.
pub(super) fn canonical_u64_header<B>(request: &Request<B>, name: &'static str) -> Option<u64> {
    let values = request.headers().get_all(name);
    let mut values = values.iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some()
        || value.is_empty()
        || value.starts_with('+')
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    let parsed = value.parse::<u64>().ok()?;
    (parsed.to_string() == value).then_some(parsed)
}

/// Parses strict bridge negotiation metadata without trusting it for authentication.
pub(super) fn carrier_request<B>(request: &Request<B>, host: &str) -> Option<CarrierRequest> {
    let user_agent_hash = normalized_user_agent_hash(request)?;
    let capabilities = single_header(request, "x-carrier-capabilities");
    let attempt = optional_canonical_u8_header(request, "x-carrier-attempt")?;
    let failure = optional_failure_header(request)?;
    let native_ios = native_ios_user_agent(request);
    match (capabilities, attempt) {
        (None, None) if failure.is_none() => {
            if native_ios {
                Some(CarrierRequest::ios(user_agent_hash))
            } else {
                Some(CarrierRequest::legacy(user_agent_hash))
            }
        }
        (Some(capabilities), Some(attempt)) => {
            let capabilities = parse_capabilities(capabilities)?;
            let capabilities = if native_ios {
                capabilities.intersection(CarrierCapabilities::ios())?
            } else {
                capabilities
            };
            if (attempt == 1) != failure.is_none() {
                return None;
            }
            Some(CarrierRequest::automatic(
                if native_ios {
                    CarrierClientClass::Ios
                } else {
                    CarrierClientClass::Bridge
                },
                capabilities,
                attempt,
                failure,
                user_agent_hash,
            ))
        }
        (None, Some(attempt)) if strict_browser_hint(request, host) => {
            if native_ios {
                return None;
            }
            if (attempt == 1) != failure.is_none() {
                return None;
            }
            Some(CarrierRequest::automatic(
                CarrierClientClass::BrowserHint,
                CarrierCapabilities::all(),
                attempt,
                failure,
                user_agent_hash,
            ))
        }
        _ => None,
    }
}

fn native_ios_user_agent<B>(request: &Request<B>) -> bool {
    single_header(request, header::USER_AGENT).is_some_and(|value| {
        let value = value.to_ascii_lowercase();
        value.contains("cfnetwork/") && value.contains("darwin/")
    })
}

fn parse_capabilities(value: &str) -> Option<CarrierCapabilities> {
    let mut bits = 0u8;
    let mut previous = None;
    for token in value.split(',') {
        let index = match token {
            "https" => 0,
            "https-lanes" => 1,
            "websocket" => 2,
            "websocket-lanes" => 3,
            _ => return None,
        };
        if previous.is_some_and(|previous| index <= previous) {
            return None;
        }
        previous = Some(index);
        bits |= 1 << index;
    }
    CarrierCapabilities::from_bits(bits)
}

fn strict_browser_hint<B>(request: &Request<B>, host: &str) -> bool {
    single_header(request, header::ORIGIN).is_some_and(|value| value == format!("https://{host}"))
        && single_header(request, "sec-fetch-site") == Some("same-origin")
        && single_header(request, "sec-fetch-mode") == Some("cors")
        && single_header(request, "sec-fetch-dest") == Some("empty")
}

fn optional_canonical_u8_header<B>(request: &Request<B>, name: &'static str) -> Option<Option<u8>> {
    if !request.headers().contains_key(name) {
        return Some(None);
    }
    canonical_u64_header(request, name)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|value| (1..=4).contains(value))
        .map(Some)
}

pub(super) fn optional_failure_header<B>(request: &Request<B>) -> Option<Option<CarrierFailure>> {
    if !request.headers().contains_key("x-carrier-failure") {
        return Some(None);
    }
    single_header(request, "x-carrier-failure")
        .and_then(CarrierFailure::parse)
        .map(Some)
}

fn normalized_user_agent_hash<B>(request: &Request<B>) -> Option<[u8; 32]> {
    let user_agent = match single_header(request, header::USER_AGENT) {
        Some(value) => value.as_bytes(),
        None if !request.headers().contains_key(header::USER_AGENT) => &[],
        None => return None,
    };
    let mut digest = Sha256::new();
    digest.update(USER_AGENT_CONTEXT);
    let mut emitted = false;
    let mut pending_whitespace = false;
    for &byte in user_agent {
        if byte.is_ascii_whitespace() {
            pending_whitespace = emitted;
        } else {
            if pending_whitespace {
                digest.update([b' ']);
            }
            digest.update([byte.to_ascii_lowercase()]);
            emitted = true;
            pending_whitespace = false;
        }
    }
    Some(digest.finalize().into())
}

fn single_header<B>(request: &Request<B>, name: impl header::AsHeaderName) -> Option<&str> {
    let mut values = request.headers().get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    values.next().is_none().then_some(value)
}

// Canonical request parsing and client-classification tests.
#[cfg(test)]
#[path = "request/tests.rs"]
mod tests;
